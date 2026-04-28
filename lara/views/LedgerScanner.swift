//
//  LedgerScanner.swift
//  lara
//
//  Finds and caches the kernel address of each process's physical footprint
//  ledger entry, then writes directly to it via KRW.
//
//  Why this is necessary
//  ─────────────────────
//  All memorystatus_control commands (5, 6, 9) and task_set_phys_footprint_limit
//  pass through task_set_phys_footprint_limit_internal in XNU, which silently
//  clamps the new value against an entitlement-gated ceiling (~2.2 GB on 4 GB
//  devices). The call returns KERN_SUCCESS regardless, making the clamp
//  invisible to callers.
//
//  The VM page fault handler reads the ledger's le_limit field directly with
//  no re-validation. Writing via kwrite64 bypasses every entitlement check and
//  every software clamp.
//
//  How the scanner works
//  ─────────────────────
//  1. Sets a known canary value on LARA'S OWN process via memorystatus cmd6
//     routed through configd (which is root). Using lara's own process means
//     the target app is never disturbed during the scan.
//  2. Reads lara's kernel task struct with kread64 to find the ledger pointer.
//  3. Scans the ledger region for the canary to locate le_limit.
//  4. Derives all struct offsets (entry stride, phys_footprint index) and
//     validates them by readback.
//  5. Caches the result — all subsequent applies are RC-free (KRW only).
//
//  Struct layout reference (xnu-10002.81.5 — stable across iOS 17/18/26)
//  ──────────────────────────────────────────────────────────────────────
//  struct task {
//      ...
//      ledger_t  ledger;               // ≈ +0x98 — pointer to struct ledger
//      ...
//  }
//  struct ledger {
//      lck_spin_t  ...                 // +0x00  small integer (lock word)
//      ledger_template_t *template;    // +0x08  kernel pointer
//      ...
//      struct ledger_entry entries[];  // variable offset after header
//  }
//  struct ledger_entry {
//      int16_t  le_flags;              // +0x00
//      int16_t  le_pad;                // +0x02
//      uint32_t le_refs;               // +0x04
//      int64_t  le_credit;             // +0x08
//      int64_t  le_debit;              // +0x10
//      int64_t  le_limit;              // +0x18  ← write here
//      int64_t  le_warn_level;         // +0x20
//      ...                             // sizeof = 0x60
//  }
//  TASK_LEDGER_PHYS_FOOTPRINT = 7     (stable from iOS 15 through 26)
//

import Foundation
import Darwin

// MARK: - LedgerOffsets

struct LedgerOffsets: CustomStringConvertible {
    /// Offset of `ledger_t` pointer within `struct task`
    let off_task_ledger:      UInt64
    /// Byte offset of `entries[]` from the start of `struct ledger`
    let off_ledger_entries:   UInt64
    /// Byte offset of `le_limit` within one `struct ledger_entry`
    let off_le_limit:         UInt64
    /// sizeof(struct ledger_entry) — stride of the entries array
    let sizeof_ledger_entry:  UInt64
    /// Index of TASK_LEDGER_PHYS_FOOTPRINT in the entries array
    let idx_phys_footprint:   UInt64

    /// Precomputed offset from ledger base to the limit field
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

    // Thread-safe cached offsets. Written once, never mutated.
    private(set) static var cached: LedgerOffsets? = nil
    private static let cacheLock = NSLock()

    // memorystatus commands used internally
    private static let CMD_GET_MEMLIMIT: Int32  = 8  // GET_MEMLIMIT_PROPERTIES
    private static let CMD_SET_TASK_LIMIT: Int32 = 6  // SET_JETSAM_TASK_LIMIT
    private static let SYS_MEMORYSTATUS: UInt64 = 396 // iOS 17.x (xnu-10002.81.5)

    // ── Run scanner ───────────────────────────────────────────────────────────
    //
    // MUST be called from a background thread.
    // rcCapture: (rc, trojan) must be obtained on the main thread first
    //            (pool access is main-thread-safe) and passed in here.
    //
    @discardableResult
    static func runScanner(
        rcCapture: (rc: RemoteCall, trojan: UInt64),
        rcio: RemoteFileIO
    ) -> LedgerResult {
        let mgr = laramgr.shared

        // Already cached — return immediately
        if let c = cached {
            return ok("already cached: \(c)")
        }

        guard mgr.dsready else {
            return fail("KRW not ready — run exploit first")
        }

        var log = ""
        func note(_ s: String) {
            log += s + "\n"
            print("[LedgerScanner] \(s)")
        }

        let rc     = rcCapture.rc
        let trojan = rcCapture.trojan
        let myPid  = Int32(getpid())

        // ── 1. Resolve lara's own task address ─────────────────────────────
        note("1. resolving own task address")
        let myTask = task_self()
        guard myTask != 0, isKernelPtr(myTask) else {
            return fail("task_self() returned invalid address 0x\(h(myTask))", log: log)
        }
        note("   task @ 0x\(h(myTask))")

        // ── 2. Read current limit (so we can restore after scan) ───────────
        note("2. reading current memory limit via RC")
        var origLimitMB: Int32 = 0
        do {
            var zeroBuf = [UInt8](repeating: 0, count: 16)
            zeroBuf.withUnsafeBytes { b in
                rc.remote_write(trojan, from: b.baseAddress, size: UInt64(16))
            }
            let getRetRaw = rcio.callIn(rc: rc, name: "syscall", args: [
                SYS_MEMORYSTATUS,
                UInt64(CMD_GET_MEMLIMIT),
                UInt64(myPid),
                0, trojan, 16
            ], timeout: 1000)
            let getRet = Int32(bitPattern: UInt32(getRetRaw & 0xFFFF_FFFF))

            if getRet == 0 {
                var readBuf = [UInt8](repeating: 0, count: 16)
                _ = readBuf.withUnsafeMutableBytes { p in
                    rc.remoteRead(trojan, to: p.baseAddress, size: UInt64(16))
                }
                origLimitMB = readBuf.withUnsafeBytes { $0.load(as: Int32.self) }
                note("   original limit: \(origLimitMB) MB")
            } else {
                note("   GET_MEMLIMIT failed (ret \(getRet)) — will restore to 0")
            }
        }

        // ── 3. Set canary on lara's own process ────────────────────────────
        // 877 MB: unique, well below the system clamp, not a typical limit value.
        let canaryMB:    Int32 = 877
        let canaryBytes: Int64 = Int64(canaryMB) * 1024 * 1024  // 919,699,456

        note("3. setting canary \(canaryMB) MB on own pid \(myPid) via RC")
        let setRetRaw = rcio.callIn(rc: rc, name: "syscall", args: [
            SYS_MEMORYSTATUS,
            UInt64(CMD_SET_TASK_LIMIT),
            UInt64(myPid),
            UInt64(canaryMB), 0, 0
        ], timeout: 1000)
        let setRet = Int32(bitPattern: UInt32(setRetRaw & 0xFFFF_FFFF))
        guard setRet == 0 else {
            return fail("SET_JETSAM_TASK_LIMIT returned \(setRet) — is configd RC ready?", log: log)
        }
        note("   canary set OK")
        usleep(10_000)   // brief yield — write is synchronous but scheduler may need a tick

        // ── 4. Find ledger pointer in task struct ──────────────────────────
        note("4. locating ledger pointer in task struct")
        guard let taskBuf = kreadBytes(myTask, count: 0x200, mgr: mgr) else {
            restore(rc: rc, rcio: rcio, trojan: trojan, pid: myPid, origMB: origLimitMB)
            return fail("kread of task struct failed", log: log)
        }

        var ledgerPtr:     UInt64 = 0
        var off_task_ledger: UInt64 = 0

        // Candidate offsets in decreasing probability order for iOS 17/18/26.
        // The scanner validates each candidate before accepting.
        for off: UInt64 in [0x98, 0x88, 0x90, 0xA0, 0xA8, 0x80, 0xB0, 0xC0, 0x70] {
            guard Int(off) + 8 <= taskBuf.count else { continue }
            let candidate = taskBuf.withUnsafeBytes {
                $0.load(fromByteOffset: Int(off), as: UInt64.self)
            }
            guard isKernelPtr(candidate) else { continue }

            // Ledger struct heuristic:
            //   word0 (lock): small integer < 0x10000
            //   word1 (template pointer): valid kernel pointer
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
            restore(rc: rc, rcio: rcio, trojan: trojan, pid: myPid, origMB: origLimitMB)
            return fail("ledger pointer not found in task struct", log: log)
        }

        // ── 5. Scan ledger region for canary ───────────────────────────────
        note("5. scanning 0x800 bytes of ledger for canary 0x\(h(UInt64(bitPattern: canaryBytes)))")
        guard let ledgerBuf = kreadBytes(ledgerPtr, count: 0x800, mgr: mgr) else {
            restore(rc: rc, rcio: rcio, trojan: trojan, pid: myPid, origMB: origLimitMB)
            return fail("kread of ledger region failed", log: log)
        }

        var canaryOffset: Int? = nil
        ledgerBuf.withUnsafeBytes { raw in
            var i = 0
            while i + 8 <= raw.count {
                if raw.load(fromByteOffset: i, as: Int64.self) == canaryBytes {
                    canaryOffset = i
                    break
                }
                i += 8   // le_limit is 8-byte aligned
            }
        }
        guard let cOff = canaryOffset else {
            restore(rc: rc, rcio: rcio, trojan: trojan, pid: myPid, origMB: origLimitMB)
            return fail("canary not found in ledger region — cmd6 may have been intercepted", log: log)
        }
        note("   canary found at ledger+0x\(h(UInt64(cOff)))")

        // ── 6. Confirm entry stride ────────────────────────────────────────
        // sizeof(struct ledger_entry) is 0x60 in xnu-10002.81.5 and subsequent.
        // Validate by checking that adjacent entries contain plausible limit values
        // (positive, < 16 GB in bytes, distinct from canary).
        note("6. confirming entry stride")
        var stride: UInt64 = 0

        for s: UInt64 in [0x60, 0x50, 0x70, 0x80] {
            var validNeighbours = 0
            for delta in [-Int(s), Int(s)] {
                let n = cOff + delta
                guard n >= 0, n + 8 <= ledgerBuf.count else { continue }
                let v = ledgerBuf.withUnsafeBytes {
                    $0.load(fromByteOffset: n, as: Int64.self)
                }
                // Plausible limit: positive bytes, < 16 GB, not our canary
                if v > 0, v != canaryBytes, v < 16 * 1024 * 1024 * 1024 {
                    validNeighbours += 1
                }
            }
            if validNeighbours > 0 {
                stride = s
                note("   stride = 0x\(h(s)) (\(validNeighbours) valid neighbour(s))")
                break
            }
        }

        guard stride != 0 else {
            restore(rc: rc, rcio: rcio, trojan: trojan, pid: myPid, origMB: origLimitMB)
            return fail("could not confirm entry stride", log: log)
        }

        // ── 7. Confirm off_le_limit within entry ───────────────────────────
        // XNU: le_limit is at +0x18 from the entry base.
        // Validate by checking credit (+0x08) and debit (+0x10) are both ≥ 0.
        note("7. confirming le_limit offset within entry")
        var off_le_limit: UInt64 = 0

        for lOff: UInt64 in [0x18, 0x10, 0x20, 0x28] {
            let eBase = Int(cOff) - Int(lOff)
            guard eBase >= 0, eBase + 0x18 <= ledgerBuf.count else { continue }
            let credit = ledgerBuf.withUnsafeBytes {
                $0.load(fromByteOffset: eBase + 0x08, as: Int64.self)
            }
            let debit = ledgerBuf.withUnsafeBytes {
                $0.load(fromByteOffset: eBase + 0x10, as: Int64.self)
            }
            // credit and debit must be non-negative and below device RAM (sanity)
            if credit >= 0, debit >= 0, credit < 8 * 1024 * 1024 * 1024 {
                off_le_limit = lOff
                note("   off_le_limit = +0x\(h(lOff)) (credit=\(credit/1024)KB debit=\(debit/1024)KB)")
                break
            }
        }

        if off_le_limit == 0 {
            // All candidates failed validation — use XNU prior and warn
            off_le_limit = 0x18
            note("   WARNING: le_limit validation inconclusive; using XNU prior +0x18")
        }

        // ── 8. Determine phys_footprint index ──────────────────────────────
        // TASK_LEDGER_PHYS_FOOTPRINT = 7 in XNU (stable from iOS 15 through 26).
        // Derive entries_base = cOff - (idx * stride) - off_le_limit.
        // Sanity check: entries_base must fall after the ledger header (≥ 0x10)
        // and before a plausible boundary (< 0x100).
        note("8. determining phys_footprint ledger index")
        var foundIdx:    UInt64? = nil
        var entriesBase: UInt64  = 0

        for idx: UInt64 in [7, 6, 8, 5, 9] {
            let base = Int(cOff) - Int(idx * stride) - Int(off_le_limit)
            if base >= 0x10, base < 0x100 {
                foundIdx    = idx
                entriesBase = UInt64(base)
                note("   idx=\(idx) → entries @ ledger+0x\(h(UInt64(base)))")
                break
            }
        }

        guard let idx = foundIdx else {
            restore(rc: rc, rcio: rcio, trojan: trojan, pid: myPid, origMB: origLimitMB)
            return fail("could not determine phys_footprint index", log: log)
        }

        // ── 9. Restore original limit ──────────────────────────────────────
        note("9. restoring original limit (\(origLimitMB > 0 ? "\(origLimitMB) MB" : "system default"))")
        restore(rc: rc, rcio: rcio, trojan: trojan, pid: myPid, origMB: origLimitMB)
        usleep(15_000)

        // ── 10. Readback validation ────────────────────────────────────────
        // After restore the ledger should reflect the original limit.
        // A match confirms the computed address is correct.
        note("10. readback validation")
        let limitAddr = ledgerPtr + entriesBase + (idx * stride) + off_le_limit
        guard isKernelPtr(limitAddr) else {
            return fail("computed limit address invalid: 0x\(h(limitAddr))", log: log)
        }

        let readback = Int64(bitPattern: mgr.kread64(address: limitAddr))
        note("    le_limit @ 0x\(h(limitAddr)) = \(readback) bytes (\(readback / (1024*1024)) MB)")

        if origLimitMB > 0 {
            let expected  = Int64(origLimitMB) * 1024 * 1024
            let tolerance: Int64 = 50 * 1024 * 1024  // 50 MB — accounts for rounding
            guard abs(readback - expected) < tolerance else {
                return fail(
                    "readback \(readback/1024/1024) MB ≠ expected \(origLimitMB) MB" +
                    " (diff \(abs(readback-expected)/1024/1024) MB) — offsets incorrect",
                    log: log
                )
            }
            note("    ✓ matches expected \(origLimitMB) MB")
        } else {
            guard readback > 0 else {
                return fail("readback ≤ 0 — offsets are wrong", log: log)
            }
            note("    readback \(readback/1024/1024) MB (no baseline)")
        }

        // ── Cache and return ───────────────────────────────────────────────
        let offsets = LedgerOffsets(
            off_task_ledger:     off_task_ledger,
            off_ledger_entries:  entriesBase,
            off_le_limit:        off_le_limit,
            sizeof_ledger_entry: stride,
            idx_phys_footprint:  idx
        )
        note("✓ scanner complete")
        note("  \(offsets)")

        cacheLock.lock()
        cached = offsets
        cacheLock.unlock()

        return LedgerResult(ok: true, detail: offsets.description, log: log)
    }

    // ── Apply limit ───────────────────────────────────────────────────────────
    //
    // Writes targetMB directly to the physical footprint ledger entry for pid.
    // Requires: dsready + cached offsets. No RC needed after scanning.
    // MUST be called from a background thread.
    //
    static func applyLimit(pid: Int32, targetMB: Int32) -> LedgerResult {
        let mgr = laramgr.shared
        var log = ""
        func note(_ s: String) { log += s + "\n" }

        guard mgr.dsready else {
            return fail("KRW not ready — run exploit first")
        }
        guard let offsets = cached else {
            return fail("offsets not cached — run scanner first")
        }
        guard targetMB > 0 else {
            return fail("targetMB must be positive")
        }

        // Resolve task address for the target process
        guard let taskAddr = resolveTask(pid: pid, mgr: mgr) else {
            return fail("could not resolve task address for pid \(pid)")
        }
        note("task @ 0x\(h(taskAddr))")

        // Follow task → ledger pointer
        let ledgerPtr = mgr.kread64(address: taskAddr + offsets.off_task_ledger)
        guard isKernelPtr(ledgerPtr) else {
            return fail("ledger pointer invalid: 0x\(h(ledgerPtr))")
        }
        note("ledger @ 0x\(h(ledgerPtr))")

        // Compute the exact address of le_limit
        let limitAddr = ledgerPtr + offsets.limitFieldOffset
        guard isKernelPtr(limitAddr) else {
            return fail("limit field address out of range: 0x\(h(limitAddr))")
        }
        note("le_limit @ 0x\(h(limitAddr))")

        // Read current value for logging
        let before    = Int64(bitPattern: mgr.kread64(address: limitAddr))
        let beforeMB  = before > 0 ? Int(before / (1024 * 1024)) : 0
        note("before: \(beforeMB) MB")

        // Write
        let targetBytes = UInt64(targetMB) * 1024 * 1024
        mgr.kwrite64(address: limitAddr, value: targetBytes)

        // Readback — confirms the write landed and the address is correct
        let after = mgr.kread64(address: limitAddr)
        guard after == targetBytes else {
            return fail(
                "readback mismatch — wrote \(targetBytes) got \(after)" +
                " — offsets may have shifted; try re-scanning"
            )
        }
        note("after: \(targetMB) MB ✓")

        return LedgerResult(
            ok:     true,
            detail: "\(beforeMB) MB → \(targetMB) MB",
            log:    log
        )
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static func isKernelPtr(_ p: UInt64) -> Bool {
        p >= VM_MIN_KERNEL_ADDRESS && p < VM_MAX_KERNEL_ADDRESS
    }

    /// Resolves the kernel task address for any pid using the allproc list.
    static func resolveTask(pid: Int32, mgr: laramgr) -> UInt64? {
        // Fast path for our own process
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
    /// laramgr has no kreadbuf equivalent — this is the Swift-safe approach.
    static func kreadBytes(_ addr: UInt64, count: Int, mgr: laramgr) -> [UInt8]? {
        guard mgr.dsready else { return nil }
        guard isKernelPtr(addr) else { return nil }
        guard count > 0, count <= 0x4000 else { return nil }  // 16 KB safety cap

        let aligned = (count + 7) & ~7
        var buf     = [UInt8](repeating: 0, count: aligned)

        for offset in Swift.stride(from: 0, to: aligned, by: 8) {
            let wordAddr = addr + UInt64(offset)
            guard isKernelPtr(wordAddr) else { break }
            let word = mgr.kread64(address: wordAddr)
            withUnsafeBytes(of: word.littleEndian) { src in
                let end = min(offset + 8, aligned)
                buf.replaceSubrange(offset..<end, with: src.prefix(end - offset))
            }
        }
        return Array(buf.prefix(count))
    }

    // Restores lara's own process limit after scanning. origMB = 0 → system default.
    private static func restore(
        rc: RemoteCall, rcio: RemoteFileIO, trojan: UInt64,
        pid: Int32, origMB: Int32
    ) {
        _ = rcio.callIn(rc: rc, name: "syscall", args: [
            SYS_MEMORYSTATUS,
            UInt64(CMD_SET_TASK_LIMIT),
            UInt64(pid),
            origMB > 0 ? UInt64(origMB) : 0,
            0, 0
        ], timeout: 500)
    }

    private static func ok(_ detail: String)  -> LedgerResult { LedgerResult(ok: true,  detail: detail, log: "") }
    private static func fail(_ msg: String, log: String = "") -> LedgerResult {
        print("[LedgerScanner] ✗ \(msg)")
        return LedgerResult(ok: false, detail: msg, log: log + "FAIL: \(msg)\n")
    }

    private static func h(_ v: UInt64) -> String { String(format: "%llx", v) }
}
