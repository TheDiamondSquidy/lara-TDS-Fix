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
//  com.apple.private.memorystatus entitlement — checked before the uid test.
//  This applies even to root processes. configd, securityd, and SpringBoard
//  do not carry this entitlement, so RC through any of them returns EPERM
//  regardless of uid. cmd6 is therefore permanently off the table.
//
//  What we do instead
//  ──────────────────
//  1. Call MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES (cmd8) directly from lara.
//     cmd8 performs no entitlement or privilege check — any process can read
//     its own limit. This gives the exact le_limit value as memlimit_active_mb;
//     in the kernel le_limit stores memlimit_active_mb * 1024 * 1024 (int64_t).
//
//  2. Walk lara's own task → ledger with kread64, searching for that known byte
//     value. The phys_footprint le_limit (positive, MB-aligned, < 16 GB) is
//     uniquely identifiable among ledger entries.
//
//  3. Validate via credit/debit sanity check on the same entry.
//
//  4. Cache the derived LedgerOffsets. All subsequent applies are pure kwrite64 —
//     no RC, no entitlement, no memorystatus_control call.
//
//  Fallback chain
//  ──────────────
//  • cmd8 succeeds  → exact byte-match (most reliable)
//  • cmd8 fails     → plausibility check: value > 100 MB, < 16 GB, MB-aligned
//  • Candidate loop finds nothing → full 0x800-byte scan of ledger region
//  • Scan finds nothing → fail; caller may retry after more app memory activity
//
//  Struct layout reference (xnu-10002.81.5 — stable across iOS 17/18/26)
//  ──────────────────────────────────────────────────────────────────────
//  struct task {
//      ...
//      ledger_t  ledger;               // ≈ +0x98
//      ...
//  }
//  struct ledger {
//      uint64_t          lock_word;      // +0x00  spinlock (value < 0x10000)
//      uint32_t          l_refs;         // +0x08
//      uint32_t          l_size;         // +0x0C
//      ledger_template_t *l_template;    // +0x10  kernel pointer
//      struct ledger_entry l_entries[];  // +0x18  (most XNU; may shift)
//  }
//  struct ledger_entry {                 // sizeof = 0x60 (iOS 17/18/26)
//      int16_t  le_flags;                // +0x00
//      int16_t  le_pad;                  // +0x02
//      uint32_t le_refs;                 // +0x04
//      int64_t  le_credit;              // +0x08
//      int64_t  le_debit;               // +0x10
//      int64_t  le_limit;               // +0x18  ← kwrite64 here
//      int64_t  le_warn_level;          // +0x20
//      ...
//  }
//  TASK_LEDGER_PHYS_FOOTPRINT = 7       (stable iOS 15 → 26)
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
    /// Offset of `ledger_t` pointer within `struct task`
    let off_task_ledger:      UInt64
    /// Byte offset of `entries[]` from the start of `struct ledger`
    let off_ledger_entries:   UInt64
    /// Byte offset of `le_limit` within one `struct ledger_entry`
    let off_le_limit:         UInt64
    /// sizeof(struct ledger_entry) — stride between array elements
    let sizeof_ledger_entry:  UInt64
    /// Index of TASK_LEDGER_PHYS_FOOTPRINT in the entries array
    let idx_phys_footprint:   UInt64

    /// Precomputed byte offset from the ledger base directly to le_limit.
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

    /// Thread-safe cached offsets. Written once after a successful scan; never mutated.
    private(set) static var cached: LedgerOffsets? = nil
    private static let cacheLock = NSLock()

    // ── Scanner ───────────────────────────────────────────────────────────────
    //
    // Locates the physical footprint le_limit field in lara's own kernel task
    // struct and caches the resulting LedgerOffsets.
    //
    // Prerequisites: dsready (KRW) only.
    //   No RC. No memorystatus entitlements. No cmd6.
    //
    // MUST be called from a background thread.
    //
    @discardableResult
    static func runScanner() -> LedgerResult {
        let mgr = laramgr.shared

        if let c = cached { return ok("already cached: \(c)") }
        guard mgr.dsready  else { return fail("KRW not ready — run exploit first") }

        var log = ""
        func note(_ s: String) { log += s + "\n"; print("[LedgerScanner] \(s)") }

        // ── 1. Own task address ────────────────────────────────────────────
        note("1. own task address via task_self()")
        let myTask = task_self()
        guard myTask != 0, isKernelPtr(myTask) else {
            return fail("task_self() returned invalid address 0x\(h(myTask))", log: log)
        }
        note("   task @ 0x\(h(myTask))")

        // ── 2. Known limit value from cmd8 ────────────────────────────────
        //
        // MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES (cmd8) has no entitlement or
        // privilege check. The call is made directly from lara's process context.
        // In the kernel, le_limit = memlimit_active_mb * 1024 * 1024 (exact, no
        // rounding), so the byte value we derive here is precisely what the ledger
        // entry stores.
        //
        // If cmd8 fails (sandbox still blocking the syscall in some edge case),
        // the scan falls back to an MB-alignment plausibility filter, which is
        // permissive enough to work but slightly less precise.
        //
        note("2. reading own memlimit via cmd8 (no privilege required)")
        var knownLimitBytes: Int64? = nil
        do {
            var buf = [UInt8](repeating: 0, count: 16)
            let ret = buf.withUnsafeMutableBytes { ptr in
                _memorystatus_control(CMD_GET_MEMLIMIT, getpid(), 0, ptr.baseAddress, 16)
            }
            if ret == 0 {
                // memlimit_active_mb is a 32-bit signed int at offset 0 of the buffer
                let mb = buf.withUnsafeBytes { $0.load(as: Int32.self) }
                if mb > 0 {
                    knownLimitBytes = Int64(mb) * 1024 * 1024
                    note("   known limit: \(mb) MB = \(knownLimitBytes!) bytes")
                } else {
                    note("   limit returned \(mb) (unlimited?) — plausibility fallback active")
                }
            } else {
                note("   cmd8 returned \(ret) (errno \(errno)) — plausibility fallback active")
            }
        }

        // ── 3. Find ledger pointer in task struct ──────────────────────────
        note("3. locating ledger pointer in task struct")
        guard let taskBuf = kreadBytes(myTask, count: 0x200, mgr: mgr) else {
            return fail("kread of task struct failed", log: log)
        }

        var ledgerPtr:       UInt64 = 0
        var off_task_ledger: UInt64 = 0

        // Candidate offsets in approximate probability order for iOS 17/18/26.
        for off: UInt64 in [0x98, 0x88, 0x90, 0xA0, 0xA8, 0x80, 0xB0, 0xC0, 0x70] {
            guard Int(off) + 8 <= taskBuf.count else { continue }
            let candidate = taskBuf.withUnsafeBytes {
                $0.load(fromByteOffset: Int(off), as: UInt64.self)
            }
            guard isKernelPtr(candidate) else { continue }

            // Ledger heuristic: lock_word at +0x00 is a small integer; l_template
            // at +0x10 is a valid kernel pointer.
            guard let hdr = kreadBytes(candidate, count: 24, mgr: mgr) else { continue }
            let w0 = hdr.withUnsafeBytes { $0.load(fromByteOffset:  0, as: UInt64.self) }
            let w2 = hdr.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt64.self) }
            guard w0 < 0x10000, isKernelPtr(w2) else { continue }

            ledgerPtr       = candidate
            off_task_ledger = off
            note("   off_task_ledger = +0x\(h(off)) → ledger @ 0x\(h(candidate))")
            break
        }
        guard ledgerPtr != 0 else {
            return fail("ledger pointer not found in task struct", log: log)
        }

        // ── 4. Locate le_limit via candidate combination search ────────────
        //
        // Iterate over the most likely (entriesOff, stride, idx, leLimitOff)
        // tuples. XNU priors come first so the correct combination is almost
        // always found on the first iteration, making the total kread64 cost
        // for the happy path just 3 reads (value + credit + debit).
        //
        // Validation:
        //   • knownLimitBytes available → exact match required
        //   • knownLimitBytes absent    → plausibility: > 100 MB, < 16 GB, MB-aligned
        //   In both cases: credit ≥ 0, debit ≥ 0, credit < 8 GB (sanity)
        //
        note("4. locating phys_footprint le_limit")

        let entriesCandidates: [UInt64] = [0x18, 0x10, 0x20, 0x28, 0x30]
        let strideCandidates:  [UInt64] = [0x60, 0x50, 0x70, 0x80]
        let idxCandidates:     [UInt64] = [7, 6, 8, 5, 9]
        let leLimitCandidates: [UInt64] = [0x18, 0x10, 0x20, 0x28]

        var foundLimitAddr: UInt64?        = nil
        var foundOffsets:   LedgerOffsets? = nil

        outer: for entriesOff in entriesCandidates {
            for stride in strideCandidates {
                for idx in idxCandidates {
                    for leLimitOff in leLimitCandidates {

                        let limitAddr = ledgerPtr + entriesOff + (idx * stride) + leLimitOff
                        guard isKernelPtr(limitAddr) else { continue }

                        let value = Int64(bitPattern: mgr.kread64(address: limitAddr))

                        let valueOK: Bool
                        if let known = knownLimitBytes {
                            valueOK = (value == known)
                        } else {
                            valueOK = value > 100 * 1024 * 1024 &&
                                      value < 16  * 1024 * 1024 * 1024 &&
                                      (value % (1024 * 1024)) == 0
                        }
                        guard valueOK else { continue }

                        // Structural sanity: credit and debit on this entry
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
                        note("     le_limit @ 0x\(h(limitAddr)) = \(value/(1024*1024)) MB")
                        note("     credit=\(credit/1024) KB  debit=\(debit/1024) KB")

                        foundLimitAddr = limitAddr
                        foundOffsets   = LedgerOffsets(
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

        // ── 5. Byte-scan fallback ──────────────────────────────────────────
        if foundLimitAddr == nil {
            note("5. candidate combinations exhausted — byte-scanning ledger region")
            if let (addr, offs) = byteScan(
                ledgerPtr:       ledgerPtr,
                off_task_ledger: off_task_ledger,
                knownLimitBytes: knownLimitBytes,
                mgr:             mgr,
                note:            note
            ) {
                foundLimitAddr = addr
                foundOffsets   = offs
            }
        } else {
            note("5. (byte-scan skipped — candidate loop succeeded)")
        }

        guard let limitAddr = foundLimitAddr,
              let offsets   = foundOffsets else {
            return fail(
                "le_limit field not found — try re-running after more app memory activity",
                log: log
            )
        }

        // ── 6. Final readback ──────────────────────────────────────────────
        note("6. readback validation")
        let rb = Int64(bitPattern: mgr.kread64(address: limitAddr))
        guard rb > 0, rb < 16 * 1024 * 1024 * 1024 else {
            return fail("readback \(rb) implausible — offsets wrong", log: log)
        }
        note("   ✓ \(rb/(1024*1024)) MB @ 0x\(h(limitAddr))")

        // ── Cache ──────────────────────────────────────────────────────────
        cacheLock.lock()
        cached = offsets
        cacheLock.unlock()

        note("✓ scanner complete: \(offsets)")
        return LedgerResult(ok: true, detail: offsets.description, log: log)
    }

    // ── Byte-scan fallback ────────────────────────────────────────────────────
    //
    // Reads the full 0x800-byte ledger region and scans 8-byte-aligned positions
    // for a plausible le_limit value, then derives all other offsets from it.
    // Only reached when none of the ~144 candidate combinations matched.
    //
    private static func byteScan(
        ledgerPtr:       UInt64,
        off_task_ledger: UInt64,
        knownLimitBytes: Int64?,
        mgr:             laramgr,
        note:            (String) -> Void
    ) -> (addr: UInt64, offsets: LedgerOffsets)? {

        guard let ledgerBuf = kreadBytes(ledgerPtr, count: 0x800, mgr: mgr) else {
            note("   byte scan: kread of 0x800 bytes failed")
            return nil
        }
        note("   byte scan: scanning 0x\(String(format: "%x", ledgerBuf.count)) bytes")

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
                              value < 16  * 1024 * 1024 * 1024 &&
                              (value % (1024 * 1024)) == 0
                }

                if valueOK {
                    note("   candidate at ledger+0x\(String(format: "%x", i))" +
                         " = \(value/(1024*1024)) MB")

                    for leLimitOff: UInt64 in [0x18, 0x10, 0x20, 0x28] {
                        let eBase = i - Int(leLimitOff)
                        guard eBase >= 0, eBase + 0x18 <= raw.count else { continue }

                        let credit = raw.load(fromByteOffset: eBase + 0x08, as: Int64.self)
                        let debit  = raw.load(fromByteOffset: eBase + 0x10, as: Int64.self)
                        guard credit >= 0, debit >= 0,
                              credit < 8 * 1024 * 1024 * 1024 else { continue }

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
    //
    // MUST be called from a background thread.
    //
    static func applyLimit(pid: Int32, targetMB: Int32) -> LedgerResult {
        let mgr = laramgr.shared
        var log = ""
        func note(_ s: String) { log += s + "\n" }

        guard mgr.dsready         else { return fail("KRW not ready — run exploit first") }
        guard let offsets = cached else { return fail("offsets not cached — run scanner first") }
        guard targetMB > 0         else { return fail("targetMB must be positive") }

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
            return fail(
                "readback mismatch: wrote \(targetBytes) got \(after)" +
                " — offsets may have shifted; try re-scanning"
            )
        }
        note("after: \(targetMB) MB ✓")

        return LedgerResult(ok: true, detail: "\(beforeMB) MB → \(targetMB) MB", log: log)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static func isKernelPtr(_ p: UInt64) -> Bool {
        p >= VM_MIN_KERNEL_ADDRESS && p < VM_MAX_KERNEL_ADDRESS
    }

    /// Resolves the kernel task address for any pid via the allproc list.
    /// Fast path for lara's own pid via task_self().
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
            let procRO   = mgr.kread64(address: e.kaddr  + UInt64(off_proc_p_proc_ro))
            guard isKernelPtr(procRO) else { continue }
            let taskAddr = mgr.kread64(address: procRO   + UInt64(off_proc_ro_pr_task))
            guard isKernelPtr(taskAddr) else { continue }
            return taskAddr
        }
        return nil
    }

    /// Reads `count` bytes from a kernel address via repeated kread64.
    /// laramgr exposes no kreadbuf — this is the safe Swift-layer equivalent.
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

    private static func ok(_ d: String) -> LedgerResult {
        LedgerResult(ok: true, detail: d, log: "")
    }
    private static func fail(_ msg: String, log: String = "") -> LedgerResult {
        print("[LedgerScanner] ✗ \(msg)")
        return LedgerResult(ok: false, detail: msg, log: log + "FAIL: \(msg)\n")
    }
    private static func h(_ v: UInt64) -> String { String(format: "%llx", v) }
}
