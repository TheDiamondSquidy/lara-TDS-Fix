//
//  LedgerScanner.swift
//  lara
//
//  Finds and caches the kernel address of the physical footprint ledger entry,
//  then writes directly to it via kwrite64 to bypass memorystatus_control caps.
//
//  Why cmd6 is NOT used
//  ────────────────────
//  MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT (cmd6) requires the
//  com.apple.private.memorystatus entitlement. This check applies even to
//  root processes. configd, securityd, and SpringBoard do not hold this
//  entitlement. cmd6 via RC therefore returns EPERM regardless of uid.
//
//  What we do instead
//  ──────────────────
//  1. Call MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES (cmd8) directly from lara.
//     cmd8 has no entitlement or privilege check — any process can read its
//     own limit. This gives us the exact le_limit value in bytes.
//
//  2. Walk lara's own task → ledger struct with kread64, searching for that
//     known byte value. The phys_footprint le_limit (MB-aligned, < 16 GB) is
//     uniquely identifiable among ledger entries.
//
//  3. Validate by credit/debit sanity check on the same entry.
//
//  4. Cache the derived LedgerOffsets. All subsequent applies are pure kwrite64.
//     No RC. No entitlement. No memorystatus_control at all.
//
//  Struct layout reference (xnu-10002.81.5 — stable across iOS 17/18/26)
//  ──────────────────────────────────────────────────────────────────────
//  struct ledger {
//      uint64_t         lock_word;    // +0x00  spinlock (< 0x10000)
//      uint32_t         l_refs;       // +0x08
//      uint32_t         l_size;       // +0x0C
//      ledger_template_t *l_template; // +0x10  kernel pointer
//      struct ledger_entry l_entries[]; // +0x18  (typical; may vary)
//  }
//  struct ledger_entry {             // sizeof = 0x60 (iOS 17/18/26)
//      int16_t  le_flags;            // +0x00
//      int16_t  le_pad;              // +0x02
//      uint32_t le_refs;             // +0x04
//      int64_t  le_credit;           // +0x08
//      int64_t  le_debit;            // +0x10
//      int64_t  le_limit;            // +0x18  ← kwrite64 here
//      int64_t  le_warn_level;       // +0x20
//      ...
//  }
//  TASK_LEDGER_PHYS_FOOTPRINT = 7   (stable iOS 15 → 26)
//

import Foundation
import Darwin

// MARK: - memorystatus_control (cmd8 only — no privilege check on this command)

@_silgen_name("memorystatus_control")
private func _memorystatus_control(
    _ command:    Int32,
    _ pid:        Int32,
    _ flags:      UInt32,
    _ buffer:     UnsafeMutableRawPointer?,
    _ buffersize: Int
) -> Int32

private let CMD_GET_MEMLIMIT: Int32 = 8   // MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES

// MARK: - LedgerOffsets

struct LedgerOffsets: CustomStringConvertible {
    let off_task_ledger:      UInt64
    let off_ledger_entries:   UInt64
    let off_le_limit:         UInt64
    let sizeof_ledger_entry:  UInt64
    let idx_phys_footprint:   UInt64

    /// Offset from ledger base directly to the le_limit field.
    var limitFieldOffset: UInt64 {
        off_ledger_entries + (idx_phys_footprint * sizeof_ledger_entry) + off_le_limit
    }

    var description: String {
        "task_ledger=+0x\(h(off_task_ledger))" +
        " entries=+0x\(h(off_ledger_entries))" +
        " le_limit=+0x\(h(off_le_limit))" +
        " stride=0x\(h(sizeof_ledger_entry))" +
        " idx=\(idx_phys_footprint)"
    }
    private func h(_ v: UInt64) -> String { String(format: "%llx", v) }
}

// MARK: - LedgerResult

struct LedgerResult {
    let ok:     Bool
    let detail: String
    let log:    String
}

// MARK: - LedgerScanner

final class LedgerScanner {

    private(set) static var cached: LedgerOffsets? = nil
    private static let cacheLock = NSLock()

    // ── Scanner ───────────────────────────────────────────────────────────────
    //
    // Requires: dsready only (no RC, no memorystatus entitlements).
    // MUST be called from a background thread.
    //
    @discardableResult
    static func runScanner() -> LedgerResult {
        let mgr = laramgr.shared

        if let c = cached { return ok("already cached: \(c)") }
        guard mgr.dsready else { return fail("KRW not ready — run exploit first") }

        var log = ""
        func note(_ s: String) { log += s + "\n"; print("[LedgerScanner] \(s)") }

        // ── 1. Own task address ────────────────────────────────────────────
        note("1. own task address via task_self()")
        let myTask = task_self()
        guard myTask != 0, isKernelPtr(myTask) else {
            return fail("task_self() returned invalid address 0x\(h(myTask))", log: log)
        }
        note("   task @ 0x\(h(myTask))")

        // ── 2. Get own memlimit as known search value ──────────────────────
        //
        // CMD_GET_MEMLIMIT_PROPERTIES (cmd8) has NO entitlement or privilege
        // check. Any process can call it on its own pid. This gives the exact
        // le_limit value as memlimit_active_mb; in the kernel le_limit stores
        // memlimit_active_mb * 1024 * 1024 as an int64_t.
        //
        note("2. reading own memlimit via cmd8 (no privilege required)")
        var knownLimitBytes: Int64? = nil
        do {
            var buf = [UInt8](repeating: 0, count: 16)
            let ret = buf.withUnsafeMutableBytes { ptr in
                _memorystatus_control(CMD_GET_MEMLIMIT, getpid(), 0, ptr.baseAddress, 16)
            }
            if ret == 0 {
                let mb = buf.withUnsafeBytes { $0.load(as: Int32.self) }
                if mb > 0 {
                    knownLimitBytes = Int64(mb) * 1024 * 1024
                    note("   known limit: \(mb) MB = \(knownLimitBytes!) bytes")
                } else {
                    note("   limit returned 0/unlimited — using plausibility check")
                }
            } else {
                note("   cmd8 returned \(ret) (errno \(errno)) — using plausibility check")
            }
        }

        // ── 3. Find ledger pointer in task struct ──────────────────────────
        note("3. locating ledger pointer in task struct")
        guard let taskBuf = kreadBytes(myTask, count: 0x200, mgr: mgr) else {
            return fail("kread of task struct failed", log: log)
        }

        var ledgerPtr:      UInt64 = 0
        var off_task_ledger: UInt64 = 0

        for off: UInt64 in [0x98, 0x88, 0x90, 0xA0, 0xA8, 0x80, 0xB0, 0xC0, 0x70] {
            guard Int(off) + 8 <= taskBuf.count else { continue }
            let candidate = taskBuf.withUnsafeBytes {
                $0.load(fromByteOffset: Int(off), as: UInt64.self)
            }
            guard isKernelPtr(candidate) else { continue }
            // Ledger heuristic: word0 = spinlock (small int), word1 = template pointer
            guard let hdr = kreadBytes(candidate, count: 16, mgr: mgr) else { continue }
            let w0 = hdr.withUnsafeBytes { $0.load(fromByteOffset: 0, as: UInt64.self) }
            let w1 = hdr.withUnsafeBytes { $0.load(fromByteOffset: 8, as: UInt64.self) }
            guard w0 < 0x10000, isKernelPtr(w1) else { continue }
            ledgerPtr      = candidate
            off_task_ledger = off
            note("   off_task_ledger = +0x\(h(off)) → ledger @ 0x\(h(candidate))")
            break
        }
        guard ledgerPtr != 0 else {
            return fail("ledger pointer not found in task struct", log: log)
        }

        // ── 4. Locate le_limit by value match ─────────────────────────────
        //
        // Try candidate offset combinations. XNU priors come first so the fast
        // path (matching on the very first iteration) is most common.
        //
        // Validation strategy:
        //   • If cmd8 succeeded:  exact byte-match against knownLimitBytes
        //   • If cmd8 failed:     plausibility check (positive, < 16 GB, MB-aligned)
        // Either way, also check credit(+0x08) and debit(+0x10) are ≥ 0.
        //
        note("4. locating phys_footprint le_limit")

        let entriesCandidates: [UInt64] = [0x18, 0x10, 0x20, 0x28, 0x30]
        let strideCandidates:  [UInt64] = [0x60, 0x50, 0x70, 0x80]
        let idxCandidates:     [UInt64] = [7, 6, 8, 5, 9]
        let leLimitCandidates: [UInt64] = [0x18, 0x10, 0x20, 0x28]

        var foundLimitAddr:  UInt64?       = nil
        var foundOffsets:    LedgerOffsets? = nil

        outer: for entriesOff in entriesCandidates {
            for stride in strideCandidates {
                for idx in idxCandidates {
                    for leLimitOff in leLimitCandidates {

                        let limitAddr = ledgerPtr + entriesOff + (idx * stride) + leLimitOff
                        guard isKernelPtr(limitAddr) else { continue }

                        let value = Int64(bitPattern: mgr.kread64(address: limitAddr))

                        // Value check
                        let valueOK: Bool
                        if let known = knownLimitBytes {
                            valueOK = (value == known)
                        } else {
                            // No known value — use plausibility only
                            // le_limit for phys_footprint is always a positive number
                            // of bytes that's exactly N * 1024 * 1024 (set as MB * 1MiB)
                            valueOK = value > 0 &&
                                      value < 16 * 1024 * 1024 * 1024 &&
                                      (value % (1024 * 1024)) == 0
                        }
                        guard valueOK else { continue }

                        // Structural check: credit and debit on the same entry
                        // must be non-negative and plausible
                        let entryBase  = limitAddr &- leLimitOff
                        let creditAddr = entryBase + 0x08
                        let debitAddr  = entryBase + 0x10
                        guard isKernelPtr(creditAddr), isKernelPtr(debitAddr) else { continue }

                        let credit = Int64(bitPattern: mgr.kread64(address: creditAddr))
                        let debit  = Int64(bitPattern: mgr.kread64(address: debitAddr))
                        guard credit >= 0, debit >= 0,
                              credit < 8 * 1024 * 1024 * 1024 else { continue }

                        note("   ✓ entries=+0x\(h(entriesOff)) stride=0x\(h(stride))" +
                             " idx=\(idx) le_limit=+0x\(h(leLimitOff))")
                        note("     le_limit @ 0x\(h(limitAddr)) = \(value / (1024*1024)) MB")
                        note("     credit=\(credit/1024)KB debit=\(debit/1024)KB")

                        foundLimitAddr = limitAddr
                        foundOffsets = LedgerOffsets(
                            off_task_ledger:     off_task_ledger,
                            off_ledger_entries:  entriesOff,
                            off_le_limit:        leLimitOff,
                            sizeof_ledger_entry: stride,
                            idx_phys_footprint:  idx
                        )
                        break outer
                    }
                }
            }
        }

        guard let limitAddr = foundLimitAddr,
              let offsets   = foundOffsets else {
            // Exhaustive search across the entire ledger region as last resort
            note("   candidate combinations exhausted — trying byte scan of ledger region")
            if let (addr, offs) = byteScan(
                ledgerPtr: ledgerPtr,
                off_task_ledger: off_task_ledger,
                knownLimitBytes: knownLimitBytes,
                mgr: mgr,
                note: note
            ) {
                cacheLock.lock()
                cached = offs
                cacheLock.unlock()
                note("✓ scanner complete (byte scan): \(offs)")
                return LedgerResult(ok: true, detail: offs.description, log: log)
            }
            return fail("le_limit field not found — try re-running after more app activity", log: log)
        }

        // ── 5. Final readback ─────────────────────────────────────────────
        note("5. readback validation")
        let rb = Int64(bitPattern: mgr.kread64(address: limitAddr))
        guard rb > 0, rb < 16 * 1024 * 1024 * 1024 else {
            return fail("readback \(rb) implausible — offsets wrong", log: log)
        }
        note("   ✓ \(rb / (1024*1024)) MB at 0x\(h(limitAddr))")

        cacheLock.lock()
        cached = offsets
        cacheLock.unlock()

        note("✓ scanner complete: \(offsets)")
        return LedgerResult(ok: true, detail: offsets.description, log: log)
    }

    // ── Byte scan fallback ─────────────────────────────────────────────────
    //
    // Scans the ledger region byte-by-byte for a plausible le_limit value,
    // then derives all other offsets from its position.
    // Only reached if the candidate-combination search found nothing.
    //
    private static func byteScan(
        ledgerPtr: UInt64,
        off_task_ledger: UInt64,
        knownLimitBytes: Int64?,
        mgr: laramgr,
        note: (String) -> Void
    ) -> (addr: UInt64, offsets: LedgerOffsets)? {

        guard let ledgerBuf = kreadBytes(ledgerPtr, count: 0x800, mgr: mgr) else {
            note("   byte scan: kread of 0x800 ledger bytes failed")
            return nil
        }

        note("   byte scan: scanning 0x800 bytes")

        var result: (addr: UInt64, LedgerOffsets)? = nil
        ledgerBuf.withUnsafeBytes { raw in
            var i = 0
            while i + 8 <= raw.count {
                let value = raw.load(fromByteOffset: i, as: Int64.self)

                let valueOK: Bool
                if let known = knownLimitBytes {
                    valueOK = (value == known)
                } else {
                    valueOK = value > 100 * 1024 * 1024 &&
                              value < 16 * 1024 * 1024 * 1024 &&
                              (value % (1024 * 1024)) == 0
                }

                if valueOK {
                    note("   candidate at ledger+0x\(String(format: "%x", i))" +
                         " = \(value/(1024*1024)) MB")

                    // Try to derive le_limit offset and phys_footprint index
                    for leLimitOff: UInt64 in [0x18, 0x10, 0x20, 0x28] {
                        let eBase = i - Int(leLimitOff)
                        guard eBase >= 0 else { continue }

                        // Credit/debit sanity
                        guard eBase + 0x18 <= ledgerBuf.count else { continue }
                        let credit = raw.load(fromByteOffset: eBase + 0x08, as: Int64.self)
                        let debit  = raw.load(fromByteOffset: eBase + 0x10, as: Int64.self)
                        guard credit >= 0, debit >= 0,
                              credit < 8 * 1024 * 1024 * 1024 else { continue }

                        // Entry stride and idx
                        for stride: UInt64 in [0x60, 0x50, 0x70, 0x80] {
                            for idx: UInt64 in [7, 6, 8, 5] {
                                let entriesOff = UInt64(eBase) &- (idx &* stride)
                                guard entriesOff >= 0x10, entriesOff < 0x100 else { continue }

                                let offsets = LedgerOffsets(
                                    off_task_ledger:     off_task_ledger,
                                    off_ledger_entries:  entriesOff,
                                    off_le_limit:        leLimitOff,
                                    sizeof_ledger_entry: stride,
                                    idx_phys_footprint:  idx
                                )
                                note("   byte scan found: \(offsets)")
                                result = (ledgerPtr + UInt64(i), offsets)
                                return
                            }
                        }
                    }
                }
                i += 8
            }
        }
        return result
    }

    // ── Apply limit ───────────────────────────────────────────────────────────
    //
    // Writes targetMB directly to the phys_footprint le_limit field of pid's task.
    // Requires: dsready + cached offsets. No RC. No entitlements.
    // MUST be called from a background thread.
    //
    static func applyLimit(pid: Int32, targetMB: Int32) -> LedgerResult {
        let mgr = laramgr.shared
        var log = ""
        func note(_ s: String) { log += s + "\n" }

        guard mgr.dsready        else { return fail("KRW not ready — run exploit first") }
        guard let offsets = cached else { return fail("offsets not cached — run scanner first") }
        guard targetMB > 0        else { return fail("targetMB must be positive") }

        guard let taskAddr = resolveTask(pid: pid, mgr: mgr) else {
            return fail("could not resolve task for pid \(pid)")
        }
        note("task @ 0x\(h(taskAddr))")

        let ledgerPtr = mgr.kread64(address: taskAddr + offsets.off_task_ledger)
        guard isKernelPtr(ledgerPtr) else {
            return fail("ledger pointer invalid: 0x\(h(ledgerPtr))")
        }
        note("ledger @ 0x\(h(ledgerPtr))")

        let limitAddr = ledgerPtr + offsets.limitFieldOffset
        guard isKernelPtr(limitAddr) else {
            return fail("limit field address out of range: 0x\(h(limitAddr))")
        }
        note("le_limit @ 0x\(h(limitAddr))")

        let before   = Int64(bitPattern: mgr.kread64(address: limitAddr))
        let beforeMB = before > 0 ? Int(before / (1024 * 1024)) : 0
        note("before: \(beforeMB) MB")

        let targetBytes = UInt64(targetMB) * 1024 * 1024
        mgr.kwrite64(address: limitAddr, value: targetBytes)

        let after = mgr.kread64(address: limitAddr)
        guard after == targetBytes else {
            return fail("readback mismatch: wrote \(targetBytes) got \(after)" +
                        " — try re-scanning")
        }
        note("after: \(targetMB) MB ✓")

        return LedgerResult(ok: true, detail: "\(beforeMB) MB → \(targetMB) MB", log: log)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static func isKernelPtr(_ p: UInt64) -> Bool {
        p >= VM_MIN_KERNEL_ADDRESS && p < VM_MAX_KERNEL_ADDRESS
    }

    static func resolveTask(pid: Int32, mgr: laramgr) -> UInt64? {
        if pid == getpid() {
            let t = task_self()
            return (t != 0 && isKernelPtr(t)) ? t : nil
        }
        var count: Int32 = 0
        guard let ptr = proclist(nil, &count), count > 0 else { return nil }
        defer { free_proclist(ptr) }
        for i in 0..<Int(count) {
            let e = ptr[i]
            guard Int32(e.pid) == pid, e.kaddr != 0 else { continue }
            let procRO = mgr.kread64(address: e.kaddr + UInt64(off_proc_p_proc_ro))
            guard isKernelPtr(procRO) else { continue }
            let taskAddr = mgr.kread64(address: procRO + UInt64(off_proc_ro_pr_task))
            guard isKernelPtr(taskAddr) else { continue }
            return taskAddr
        }
        return nil
    }

    /// Reads `count` bytes from a kernel address using repeated kread64.
    /// laramgr provides no kreadbuf — this is the safe Swift equivalent.
    static func kreadBytes(_ addr: UInt64, count: Int, mgr: laramgr) -> [UInt8]? {
        guard mgr.dsready, isKernelPtr(addr), count > 0, count <= 0x4000 else { return nil }
        let aligned = (count + 7) & ~7
        var buf     = [UInt8](repeating: 0, count: aligned)
        for offset in Swift.stride(from: 0, to: aligned, by: 8) {
            let wa = addr + UInt64(offset)
            guard isKernelPtr(wa) else { break }
            let word = mgr.kread64(address: wa)
            withUnsafeBytes(of: word.littleEndian) { src in
                let end = min(offset + 8, aligned)
                buf.replaceSubrange(offset..<end, with: src.prefix(end - offset))
            }
        }
        return Array(buf.prefix(count))
    }

    private static func ok(_ d: String)                        -> LedgerResult { LedgerResult(ok: true,  detail: d,   log: "") }
    private static func fail(_ msg: String, log: String = "") -> LedgerResult {
        print("[LedgerScanner] ✗ \(msg)")
        return LedgerResult(ok: false, detail: msg, log: log + "FAIL: \(msg)\n")
    }
    private static func h(_ v: UInt64) -> String { String(format: "%llx", v) }
}
