//
//  LedgerScanner.swift
//  lara
//
//  Resolves and caches the physical footprint ledger entry address for any
//  process, then writes directly to it via kwrite64 — bypassing the
//  memorystatus_control entitlement cap entirely.
//
//  Background
//  ──────────
//  All memorystatus_control commands (5, 6, 9) pass through
//  task_set_phys_footprint_limit_internal, which clamps the new value to an
//  entitlement-gated ceiling (~2.2 GB on 4 GB devices). The check fires even
//  for root processes — cmd6 via RC on configd/securityd/SpringBoard returns
//  EPERM. The only path around it is a direct kwrite64 to le_limit.
//
//  How the address is found
//  ────────────────────────
//  Ghidra analysis of xnu-10002.81.5 (iOS 17.6.1 / build 21G93) revealed:
//
//    1. task->ledger at task + 0x308.
//
//    2. The physical footprint entry is not indexed as idx*stride. Instead,
//       ledger_set_limit receives a packed descriptor from the global
//       task_ledgers.phys_footprint:
//
//         entry_base = ledger + (descriptor & 0xFFFF) * 0x10
//
//    3. le_limit is at entry_base + 0x20.
//
//    4. task_ledgers.phys_footprint is zero-initialised in the kernelcache
//       binary (shows FFFFFFFFh in Ghidra) and filled at boot by task_init().
//       Its runtime value is read via kread64 using the known static address
//       adjusted by kernslide.
//
//  Full address walk (per-apply, no scanning):
//    task_addr  = proclist → proc_ro → pr_task   (or task_self() for lara)
//    ledger     = kread64(task_addr + 0x308)
//    descriptor = kread64(static_descriptor_addr + kernslide)
//    le_limit   = ledger + (descriptor & 0xFFFF) * 0x10 + 0x20
//
//  Adding support for a new build
//  ────────────────────────────────
//  1. Download IPSW for your device + build via `ipsw download ipsw`.
//  2. Extract kernelcache: `ipsw extract --kernel <ipsw>`.
//  3. Load into Ghidra. Navigate to _Xtask_set_phys_footprint_limit, follow
//     the inner call to task_set_phys_footprint_limit_internal.
//  4. The line `*(undefined8 *)(param_1 + 0x308)` confirms off_task_ledger.
//     The second arg to ledger_set_limit is the DAT_ address of the descriptor.
//  5. Add that DAT_ static address to descriptorAddrs below.
//

import Foundation
import Darwin

// MARK: - LedgerOffsets

/// Resolved offsets for a single iOS build. Cached after the first resolve().
struct LedgerOffsets: CustomStringConvertible {

    /// kern.osversion build string this was resolved on (e.g. "21G93").
    let build: String

    /// Byte offset of ledger_t* within struct task.
    /// Confirmed 0x308 for xnu-10002.81.5. Add other versions to descriptorAddrs.
    let off_task_ledger: UInt64

    /// Low 16 bits of task_ledgers.phys_footprint descriptor (runtime value).
    /// entry_base = ledger + entryUnits * 0x10
    let entryUnits: UInt64

    /// Byte offset from ledger base directly to le_limit.
    var limitFieldOffset: UInt64 { entryUnits * 0x10 + 0x20 }

    var description: String {
        "[\(build)] task+0x\(x(off_task_ledger))→ledger +0x\(x(limitFieldOffset))→le_limit (units=0x\(x(entryUnits)))"
    }

    private func x(_ v: UInt64) -> String { String(format: "%llx", v) }
}

// MARK: - LedgerResult

struct LedgerResult {
    let ok:     Bool
    let detail: String
    let log:    String
}

// MARK: - LedgerScanner

final class LedgerScanner {

    /// Cached resolved offsets. Written once; never mutated after that.
    private(set) static var cached: LedgerOffsets? = nil
    private static let cacheLock = NSLock()

    // ── Per-build descriptor address table ────────────────────────────────────
    //
    // Static virtual address of task_ledgers.phys_footprint in the kernelcache.
    // Unslid — add kernslide before reading at runtime.
    //
    // To add a new build:
    //   kern.osversion string (sysctlbyname "kern.osversion") → static DAT_ address
    //   from Ghidra (the second argument to ledger_set_limit inside
    //   task_set_phys_footprint_limit_internal).
    //
    private static let descriptorAddrs: [String: UInt64] = [
        "21G93": 0xfffffff0078bd3d4,   // iOS 17.6.1 · xnu-10002.81.5
    ]

    // ── resolve() ─────────────────────────────────────────────────────────────
    //
    // Reads the live phys_footprint descriptor from the kernel, validates the
    // computed le_limit address against lara's own process, and caches the result.
    //
    // Requires: dsready (KRW). No RC. No memorystatus entitlements.
    // Safe:     lara's own process is used for validation — read-only, no writes.
    // Fast:     3–4 kread64 calls total.
    //
    // MUST be called from a background thread.
    //
    @discardableResult
    static func runScanner() -> LedgerResult {
        let mgr = laramgr.shared

        if let c = cached { return ok("already cached: \(c)") }
        guard mgr.dsready  else { return fail("KRW not ready — run exploit first") }

        // ── 1. Build identification ────────────────────────────────────────
        let build = kernelBuild()
        guard let staticAddr = descriptorAddrs[build] else {
            return fail(
                "build \(build) not in offset table. " +
                "Load the kernelcache for this build into Ghidra, navigate to " +
                "task_set_phys_footprint_limit_internal, and add the DAT_ address " +
                "of task_ledgers.phys_footprint to LedgerScanner.descriptorAddrs."
            )
        }

        // ── 2. Read live descriptor ────────────────────────────────────────
        //
        // The descriptor is 0xFFFFFFFF in the static binary — it is zero-
        // initialised in the data segment and populated by task_init() at boot.
        // Reading it via kread64 at runtime gives the correct packed value.
        //
        let liveAddr = staticAddr &+ mgr.kernslide
        guard isKernelPtr(liveAddr) else {
            return fail("descriptor address 0x\(x(liveAddr)) outside kernel range")
        }
        let descriptor = mgr.kread64(address: liveAddr)
        let entryUnits = descriptor & 0xFFFF
        guard entryUnits > 0, entryUnits < 0x1000 else {
            return fail(
                "descriptor at 0x\(x(liveAddr)) = 0x\(x(descriptor)) — " +
                "entryUnits \(entryUnits) implausible. " +
                "Kernel may not have finished initializing, or the static address " +
                "is wrong for this build."
            )
        }

        // ── 3. Validate against lara's own process (read-only) ────────────
        let myTask = task_self()
        guard myTask != 0, isKernelPtr(myTask) else {
            return fail("task_self() returned invalid address 0x\(x(myTask))")
        }
        let ledger = mgr.kread64(address: myTask + 0x308)
        guard isKernelPtr(ledger) else {
            return fail("task->ledger at task+0x308 = 0x\(x(ledger)) — invalid pointer")
        }
        let limitAddr = ledger + entryUnits * 0x10 + 0x20
        guard isKernelPtr(limitAddr) else {
            return fail("computed le_limit address 0x\(x(limitAddr)) out of kernel range")
        }
        let limitVal = Int64(bitPattern: mgr.kread64(address: limitAddr))
        guard limitVal > 0, limitVal < 16 * 1024 * 1024 * 1024 else {
            return fail(
                "le_limit readback \(limitVal) bytes implausible — " +
                "descriptor address may be wrong for build \(build). " +
                "Re-check the DAT_ address in Ghidra."
            )
        }

        // ── 4. Cache ───────────────────────────────────────────────────────
        let offsets = LedgerOffsets(
            build:           build,
            off_task_ledger: 0x308,
            entryUnits:      entryUnits
        )
        cacheLock.lock()
        cached = offsets
        cacheLock.unlock()

        return ok("\(offsets) — own limit \(limitVal / (1024 * 1024)) MB ✓")
    }

    // ── applyLimit() ─────────────────────────────────────────────────────────
    //
    // Writes targetMB to le_limit in the phys_footprint ledger entry for pid.
    // Requires: dsready + cached offsets. No RC. No entitlements.
    //
    // MUST be called from a background thread.
    //
    static func applyLimit(pid: Int32, targetMB: Int32) -> LedgerResult {
        let mgr = laramgr.shared

        guard mgr.dsready          else { return fail("KRW not ready — run exploit first") }
        guard let off = cached     else { return fail("not resolved — run scanner first") }
        guard targetMB > 0         else { return fail("targetMB must be > 0") }

        guard let taskAddr = resolveTask(pid: pid, mgr: mgr) else {
            return fail("could not resolve task address for pid \(pid)")
        }

        let ledger = mgr.kread64(address: taskAddr + off.off_task_ledger)
        guard isKernelPtr(ledger) else {
            return fail("task->ledger = 0x\(x(ledger)) — invalid")
        }

        let limitAddr = ledger + off.limitFieldOffset
        guard isKernelPtr(limitAddr) else {
            return fail("le_limit address 0x\(x(limitAddr)) out of range")
        }

        let before      = Int64(bitPattern: mgr.kread64(address: limitAddr))
        let beforeMB    = before > 0 ? Int(before / (1024 * 1024)) : 0
        let targetBytes = UInt64(targetMB) * 1024 * 1024

        mgr.kwrite64(address: limitAddr, value: targetBytes)

        // Readback — confirms the write landed at the correct address
        let after = mgr.kread64(address: limitAddr)
        guard after == targetBytes else {
            return fail(
                "readback mismatch: wrote \(targetBytes) read back \(after) — " +
                "re-run scanner (kernel may have been updated)"
            )
        }

        return LedgerResult(
            ok:     true,
            detail: "\(beforeMB) MB → \(targetMB) MB",
            log:    "pid \(pid): 0x\(x(limitAddr)) \(beforeMB)→\(targetMB) MB ✓"
        )
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static func isKernelPtr(_ p: UInt64) -> Bool {
        p >= VM_MIN_KERNEL_ADDRESS && p < VM_MAX_KERNEL_ADDRESS
    }

    /// Resolves the kernel task address for any pid.
    /// Fast path: lara's own pid uses task_self() directly.
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

    /// Returns the kernel build string from kern.osversion (e.g. "21G93").
    /// This matches the keys in descriptorAddrs.
    private static func kernelBuild() -> String {
        var buf  = [CChar](repeating: 0, count: 32)
        var size = buf.count
        sysctlbyname("kern.osversion", &buf, &size, nil, 0)
        return String(cString: buf)
    }

    private static func ok(_ d: String) -> LedgerResult {
        LedgerResult(ok: true, detail: d, log: "")
    }
    private static func fail(_ msg: String) -> LedgerResult {
        print("[LedgerScanner] ✗ \(msg)")
        return LedgerResult(ok: false, detail: msg, log: "FAIL: \(msg)")
    }
    private static func x(_ v: UInt64) -> String { String(format: "%llx", v) }
}
