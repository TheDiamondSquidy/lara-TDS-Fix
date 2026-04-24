//
//  JetsamView.swift
//  lara
//
//  Jetsam memory manager.
//  Uses memorystatus_control directly (post-sbx-escape) to raise process
//  priority bands and set memory limits, preventing OOM kills.
//
//  Jetsam Multiplier (Dopamine-style):
//    Reads each process's current memory limit, multiplies it by a user-chosen
//    factor (1x–4x), and writes the new limit back.  Four fallback approaches:
//      1. Direct memorystatus_control from lara's own process
//      2. RC into configd (root uid, most entitlements)
//      3. RC into any other ready root-uid process in the pool
//      4. KRW direct kernel task struct write (bypasses all entitlements)
//    Includes auto-protect timer that watches for new processes and applies
//    the multiplier automatically — closest approximation to Dopamine's
//    systemhook spawn-time behaviour.
//
//  Priority band reference:
//    0   idle / background         (killed first under pressure)
//    4   background suspended
//    5   audio background
//    8   mail / daemon
//   10   foreground app            (default)
//   12   active assertion
//   15   SpringBoard
//   16   critical daemon           (highest safe value)
//   17+  kernel protected          — never touch
//

import SwiftUI
import Darwin

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - memorystatus_control declarations
// ═══════════════════════════════════════════════════════════════════════════

@_silgen_name("memorystatus_control")
private func memorystatus_control(
    _ command: Int32,
    _ pid: Int32,
    _ flags: UInt32,
    _ buffer: UnsafeMutableRawPointer?,
    _ buffersize: Int
) -> Int32

// ── Commands ──────────────────────────────────────────────────────────────
// NOTE: SET_PRIORITY_PROPERTIES is 7 in the existing working code.
//       XNU headers show SET_MEMLIMIT_PROPERTIES also as 7 on some versions.
//       If the multiplier's GET+SET path fails (because cmd 7 is interpreted
//       as priority-set on your kernel), the fallback approaches will handle
//       it — TASK_LIMIT (cmd 6), syscall(440), and KRW all work independently.
private let MEMORYSTATUS_CMD_GET_PRIORITY_LIST:           Int32 = 1
private let MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES:     Int32 = 7  // original working value
private let MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK:  Int32 = 5
private let MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT:       Int32 = 6
private let MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES:     Int32 = 7  // may overlap with above
private let MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES:     Int32 = 8

// Bit flag for HWM hard-kill
private let MEMORYSTATUS_FLAGS_HWM_HARD: UInt32 = 0x4

// ── memorystatus_memlimit_properties_t ────────────────────────────────────
// Layout (16 bytes):
//   int32_t  memlimit_active        (offset 0)   — jetsam limit (MB) when active
//   uint32_t memlimit_active_attr   (offset 4)   — attributes bitfield
//   int32_t  memlimit_inactive      (offset 8)   — jetsam limit (MB) when inactive
//   uint32_t memlimit_inactive_attr (offset 12)  — attributes bitfield
private let kMemlimitPropsSize = 16

// Attribute bit: limit is fatal (process killed, not warned)
private let MEMORYSTATUS_MEMLIMIT_ATTR_FATAL: UInt32 = 0x1

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - KRW jetsam offsets
// ═══════════════════════════════════════════════════════════════════════════
//
// ⚠️  These offsets are NOT in offsets.h yet — they need to be added for
//     your target iOS version.  The values below are PLACEHOLDERS from
//     XNU source for iOS 16.x on A12+.  Verify against your kernelcache.
//
//     To find them:
//       1. In IDA/Ghidra, find memorystatus_update_priority_for_proc()
//       2. It writes to task+off_jetsam_priority
//       3. memorystatus_set_memlimit_properties() writes to
//          task+off_memlimit_active and task+off_memlimit_inactive
//       4. Or search for the task struct definition in your XNU source
//
//     Once found, add to offsets.h:
//       extern uint32_t off_task_jetsam_priority;
//       extern uint32_t off_task_memlimit_active;
//       extern uint32_t off_task_memlimit_inactive;
//       extern uint32_t off_task_memlimit_active_attr;
//       extern uint32_t off_task_memlimit_inactive_attr;
//
//     And initialise them in offsets.m alongside the other offset lookups.

// Placeholder offsets — replace with real values from offsets_init()
// once you've identified them for your target kernel.
private var off_task_jetsam_priority:       UInt64 = 0x0   // NOT SET
private var off_task_memlimit_active:       UInt64 = 0x0   // NOT SET
private var off_task_memlimit_inactive:     UInt64 = 0x0   // NOT SET
private var off_task_memlimit_active_attr:  UInt64 = 0x0   // NOT SET
private var off_task_memlimit_inactive_attr:UInt64 = 0x0   // NOT SET

/// Returns true if the KRW jetsam offsets have been configured (non-zero).
private var krwJetsamOffsetsReady: Bool {
    off_task_memlimit_active != 0 && off_task_memlimit_inactive != 0
}


// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Multiplier result
// ═══════════════════════════════════════════════════════════════════════════

/// Records the outcome of a multiplier application attempt.
struct MultiplierResult {
    let ok: Bool
    let approach: String          // "direct" / "rc:configd" / "rc:SpringBoard" / "krw" / etc.
    let prevActive: Int32         // original memlimit_active (MB)
    let prevInactive: Int32       // original memlimit_inactive (MB)
    let newActive: Int32          // multiplied memlimit_active (MB)
    let newInactive: Int32        // multiplied memlimit_inactive (MB)
    let detail: String

    var summary: String {
        guard ok else { return "✗ \(detail)" }
        return "✓ \(prevActive)→\(newActive) MB active, \(prevInactive)→\(newInactive) MB inactive [\(approach)]"
    }

    static func failure(_ detail: String) -> MultiplierResult {
        MultiplierResult(ok: false, approach: "none", prevActive: 0, prevInactive: 0,
                         newActive: 0, newInactive: 0, detail: detail)
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// MARK: - JetsamMultiplier engine
// ═══════════════════════════════════════════════════════════════════════════
//
// Static methods that implement the four fallback approaches.
// Each takes a pid and multiplier and returns a MultiplierResult.
// The main entry point `applyMultiplier` tries them in order.

struct JetsamMultiplier {

    // ── Main entry point ──────────────────────────────────────────────────

    /// Apply the jetsam multiplier to a single process, trying all approaches
    /// in fallback order until one succeeds.
    static func applyMultiplier(pid: Int32, multiplier: Int32, mgr: laramgr? = nil) -> MultiplierResult {
        // Approach 1: direct memorystatus_control from lara's process
        let r1 = viaDirectMemstatus(pid: pid, multiplier: multiplier)
        if r1.ok { return r1 }

        // Approach 2: RC into configd (root uid, best entitlements)
        let r2 = viaRC(pid: pid, multiplier: multiplier, targetProcess: "configd")
        if r2.ok { return r2 }

        // Approach 3: RC into any other ready root-uid process
        let rcio = RemoteFileIO.shared
        let rootProcs = ["SpringBoard", "securityd", "mediaserverd",
                         RemoteFileIO.backupDaemonName]
        for proc in rootProcs {
            let r3 = viaRC(pid: pid, multiplier: multiplier, targetProcess: proc)
            if r3.ok { return r3 }
        }

        // Approach 4: RC using syscall() — call memorystatus_control by syscall number
        // This bypasses the C wrapper and can work from any hijacked process context
        let r4 = viaSyscallRC(pid: pid, multiplier: multiplier)
        if r4.ok { return r4 }

        // Approach 5: Direct KRW kernel write
        let r5 = viaKRW(pid: pid, multiplier: multiplier)
        if r5.ok { return r5 }

        return .failure("all approaches failed for pid \(pid)")
    }

    // ── Approach 1: Direct memorystatus_control ───────────────────────────

    /// Reads current limits with GET_MEMLIMIT_PROPERTIES (cmd 8),
    /// multiplies them, writes back with SET_MEMLIMIT_PROPERTIES (cmd 7).
    /// Works if lara has the com.apple.private.memorystatus entitlement
    /// (often available post-sandbox-escape).
    private static func viaDirectMemstatus(pid: Int32, multiplier: Int32) -> MultiplierResult {
        // Step 1: Read current limits
        var buf = [UInt8](repeating: 0, count: kMemlimitPropsSize)
        let getRet = buf.withUnsafeMutableBytes { ptr in
            memorystatus_control(
                MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES,
                pid,
                0,
                ptr.baseAddress,
                kMemlimitPropsSize
            )
        }

        guard getRet == 0 else {
            return .failure("direct GET_MEMLIMIT ret=\(getRet) errno=\(errno)")
        }

        let (activeOrig, activeAttr, inactiveOrig, inactiveAttr) = parseMemlimitProps(buf)

        // Step 2: Multiply (skip negative/unlimited values)
        let newActive   = activeOrig > 0 ? activeOrig * multiplier : activeOrig
        let newInactive = inactiveOrig > 0 ? inactiveOrig * multiplier : inactiveOrig

        // Step 3: Write back
        var outBuf = buildMemlimitProps(active: newActive, activeAttr: activeAttr,
                                        inactive: newInactive, inactiveAttr: inactiveAttr)
        let setRet = outBuf.withUnsafeMutableBytes { ptr in
            memorystatus_control(
                MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES,
                pid,
                0,
                ptr.baseAddress,
                kMemlimitPropsSize
            )
        }

        guard setRet == 0 else {
            return .failure("direct SET_MEMLIMIT ret=\(setRet) errno=\(errno)")
        }

        return MultiplierResult(
            ok: true, approach: "direct",
            prevActive: activeOrig, prevInactive: inactiveOrig,
            newActive: newActive, newInactive: newInactive,
            detail: "memorystatus_control direct"
        )
    }

    // ── Approach 2/3: RC into a privileged process ────────────────────────

    /// Same memorystatus_control calls but executed inside a hijacked process
    /// via RemoteCall.  The target process (configd, SpringBoard, etc.) runs
    /// with stronger entitlements than lara.
    private static func viaRC(pid: Int32, multiplier: Int32, targetProcess: String) -> MultiplierResult {
        let rcio = RemoteFileIO.shared
        guard let rc = rcio.rcProc(for: targetProcess) else {
            return .failure("rc:\(targetProcess) not ready")
        }

        let trojan = rc.trojanMem
        guard trojan != 0 else {
            return .failure("rc:\(targetProcess) trojanMem is 0")
        }

        // Step 1: GET_MEMLIMIT_PROPERTIES via RC
        // Zero out buffer region in remote memory
        var zeroBuf = [UInt8](repeating: 0, count: kMemlimitPropsSize)
        zeroBuf.withUnsafeBytes {
            rc.remote_write(trojan, from: $0.baseAddress, size: UInt64(kMemlimitPropsSize))
        }

        let getRet = rcio.callIn(rc: rc, name: "memorystatus_control", args: [
            UInt64(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES),
            UInt64(bitPattern: Int64(pid)),
            0,
            trojan,
            UInt64(kMemlimitPropsSize)
        ])

        let getRetI32 = Int32(bitPattern: UInt32(getRet & 0xFFFFFFFF))
        guard getRetI32 == 0 else {
            return .failure("rc:\(targetProcess) GET_MEMLIMIT ret=\(getRetI32)")
        }

        // Read back the struct from remote memory
        var buf = [UInt8](repeating: 0, count: kMemlimitPropsSize)
        let readOK = buf.withUnsafeMutableBytes { ptr in
            rc.remoteRead(trojan, to: ptr.baseAddress, size: UInt64(kMemlimitPropsSize))
        }
        guard readOK else {
            return .failure("rc:\(targetProcess) remote_read failed")
        }

        let (activeOrig, activeAttr, inactiveOrig, inactiveAttr) = parseMemlimitProps(buf)

        // Step 2: Multiply
        let newActive   = activeOrig > 0 ? activeOrig * multiplier : activeOrig
        let newInactive = inactiveOrig > 0 ? inactiveOrig * multiplier : inactiveOrig

        // Step 3: SET_MEMLIMIT_PROPERTIES via RC
        var outBuf = buildMemlimitProps(active: newActive, activeAttr: activeAttr,
                                        inactive: newInactive, inactiveAttr: inactiveAttr)
        outBuf.withUnsafeBytes {
            rc.remote_write(trojan, from: $0.baseAddress, size: UInt64(kMemlimitPropsSize))
        }

        let setRet = rcio.callIn(rc: rc, name: "memorystatus_control", args: [
            UInt64(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES),
            UInt64(bitPattern: Int64(pid)),
            0,
            trojan,
            UInt64(kMemlimitPropsSize)
        ])

        let setRetI32 = Int32(bitPattern: UInt32(setRet & 0xFFFFFFFF))
        guard setRetI32 == 0 else {
            // Fallback: try SET_JETSAM_TASK_LIMIT (cmd 6) — simpler, sets both limits
            // to the same value (fatal).  Less flexible but more widely supported.
            let fallbackLimit = UInt32(newActive > 0 ? newActive : 2048)
            let taskLimitRet = rcio.callIn(rc: rc, name: "memorystatus_control", args: [
                UInt64(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT),
                UInt64(bitPattern: Int64(pid)),
                UInt64(fallbackLimit),
                0,
                0
            ])
            let tlRetI32 = Int32(bitPattern: UInt32(taskLimitRet & 0xFFFFFFFF))
            if tlRetI32 == 0 {
                return MultiplierResult(
                    ok: true, approach: "rc:\(targetProcess) (TASK_LIMIT fallback)",
                    prevActive: activeOrig, prevInactive: inactiveOrig,
                    newActive: Int32(fallbackLimit), newInactive: Int32(fallbackLimit),
                    detail: "SET_MEMLIMIT failed; TASK_LIMIT succeeded"
                )
            }
            return .failure("rc:\(targetProcess) SET_MEMLIMIT ret=\(setRetI32), TASK_LIMIT ret=\(tlRetI32)")
        }

        return MultiplierResult(
            ok: true, approach: "rc:\(targetProcess)",
            prevActive: activeOrig, prevInactive: inactiveOrig,
            newActive: newActive, newInactive: newInactive,
            detail: "memorystatus_control via \(targetProcess)"
        )
    }

    // ── Approach 4: RC syscall() ──────────────────────────────────────────
    //
    // On iOS, memorystatus_control is syscall #440.
    // Calling syscall(440, cmd, pid, flags, buf, bufsize) from any hijacked
    // process bypasses the C wrapper and can work even if the function symbol
    // isn't resolved.  This is useful if dlsym can't find "memorystatus_control"
    // in the remote process but syscall() is always available.

    private static func viaSyscallRC(pid: Int32, multiplier: Int32) -> MultiplierResult {
        let rcio = RemoteFileIO.shared
        // Try configd first, then any ready root process
        let candidates = ["configd", "SpringBoard", "securityd"]
        for proc in candidates {
            guard let rc = rcio.rcProc(for: proc) else { continue }
            let trojan = rc.trojanMem
            guard trojan != 0 else { continue }

            // Zero out remote buffer
            var zeroBuf = [UInt8](repeating: 0, count: kMemlimitPropsSize)
            zeroBuf.withUnsafeBytes {
                rc.remote_write(trojan, from: $0.baseAddress, size: UInt64(kMemlimitPropsSize))
            }

            // GET via syscall(440, 8, pid, 0, buf, 16)
            let getRet = rcio.callIn(rc: rc, name: "syscall", args: [
                440,                                      // SYS_memorystatus_control
                UInt64(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES),
                UInt64(bitPattern: Int64(pid)),
                0,
                trojan,
                UInt64(kMemlimitPropsSize)
            ])

            let getRetI32 = Int32(bitPattern: UInt32(getRet & 0xFFFFFFFF))
            guard getRetI32 == 0 else { continue }

            var buf = [UInt8](repeating: 0, count: kMemlimitPropsSize)
            let readOK = buf.withUnsafeMutableBytes { ptr in
                rc.remoteRead(trojan, to: ptr.baseAddress, size: UInt64(kMemlimitPropsSize))
            }
            guard readOK else { continue }

            let (activeOrig, activeAttr, inactiveOrig, inactiveAttr) = parseMemlimitProps(buf)

            let newActive   = activeOrig > 0 ? activeOrig * multiplier : activeOrig
            let newInactive = inactiveOrig > 0 ? inactiveOrig * multiplier : inactiveOrig

            // SET via syscall(440, 7, pid, 0, buf, 16)
            var outBuf = buildMemlimitProps(active: newActive, activeAttr: activeAttr,
                                            inactive: newInactive, inactiveAttr: inactiveAttr)
            outBuf.withUnsafeBytes {
                rc.remote_write(trojan, from: $0.baseAddress, size: UInt64(kMemlimitPropsSize))
            }

            let setRet = rcio.callIn(rc: rc, name: "syscall", args: [
                440,
                UInt64(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES),
                UInt64(bitPattern: Int64(pid)),
                0,
                trojan,
                UInt64(kMemlimitPropsSize)
            ])

            let setRetI32 = Int32(bitPattern: UInt32(setRet & 0xFFFFFFFF))
            if setRetI32 == 0 {
                return MultiplierResult(
                    ok: true, approach: "syscall-rc:\(proc)",
                    prevActive: activeOrig, prevInactive: inactiveOrig,
                    newActive: newActive, newInactive: newInactive,
                    detail: "syscall(440) via \(proc)"
                )
            }
        }

        return .failure("syscall approach failed on all candidates")
    }

    // ── Approach 5: KRW direct kernel write ───────────────────────────────
    //
    // Reads memlimit_active and memlimit_inactive from the kernel task struct
    // via darksword, multiplies, writes back.  Bypasses all entitlement checks.
    //
    // ⚠️  Requires jetsam offsets to be set in offsets.h — see the comment
    //     block at the top of this file.  If offsets are 0x0, this path is
    //     skipped entirely.

    private static func viaKRW(pid: Int32, multiplier: Int32) -> MultiplierResult {
        guard krwJetsamOffsetsReady else {
            return .failure("KRW jetsam offsets not configured (all 0x0)")
        }

        let mgr = laramgr.shared
        guard mgr.dsready else {
            return .failure("darksword not ready")
        }

        // Resolve proc → proc_ro → task address
        guard let taskAddr = resolveTaskAddr(forPid: pid) else {
            return .failure("could not resolve task addr for pid \(pid)")
        }

        // Read current values
        let activeOrig   = Int32(bitPattern: mgr.kread32(taskAddr + off_task_memlimit_active))
        let inactiveOrig = Int32(bitPattern: mgr.kread32(taskAddr + off_task_memlimit_inactive))

        // Multiply
        let newActive   = activeOrig > 0 ? activeOrig * multiplier : activeOrig
        let newInactive = inactiveOrig > 0 ? inactiveOrig * multiplier : inactiveOrig

        // Write back
        mgr.kwrite32(taskAddr + off_task_memlimit_active,   value: UInt32(bitPattern: newActive))
        mgr.kwrite32(taskAddr + off_task_memlimit_inactive, value: UInt32(bitPattern: newInactive))

        return MultiplierResult(
            ok: true, approach: "krw",
            prevActive: activeOrig, prevInactive: inactiveOrig,
            newActive: newActive, newInactive: newInactive,
            detail: "direct kernel write to task+0x\(String(format: "%x", off_task_memlimit_active))"
        )
    }

    // ── KRW helpers ───────────────────────────────────────────────────────

    /// Walk the kernel allproc list to find the task address for a given pid.
    /// Uses the existing proc offsets from offsets.h (off_proc_p_pid,
    /// off_proc_p_list_le_next, off_proc_p_proc_ro, off_proc_ro_pr_task).
    ///
    /// Fallback: if laramgr exposes a taskAddr(forPid:) helper, use that.
    private static func resolveTaskAddr(forPid pid: Int32) -> UInt64? {
        let mgr = laramgr.shared

        // Try laramgr.taskAddr(forPid:) first — it may already exist
        // (uncomment if your laramgr has this method)
        // if let addr = mgr.taskAddr(forPid: pid) { return addr }

        // Walk allproc linked list using known offsets
        // Start from the root vnode's process or the first proc in the list
        var count: Int32 = 0
        guard let ptr = proclist(nil, &count), count > 0 else { return nil }
        defer { free_proclist(ptr) }

        // proclist gives us pid and kernel addr — find matching pid
        // The proc_entry struct from utils.h includes a kaddr field
        // If your proc_entry doesn't have kaddr, use the allproc walk below instead
        for i in 0..<Int(count) {
            let e = ptr[i]
            if e.pid == UInt32(pid) {
                // e.kaddr is the kernel address of the proc struct
                // proc → proc_ro → task
                let procRO = mgr.kread64(e.kaddr + UInt64(off_proc_p_proc_ro))
                guard procRO != 0 else { return nil }
                let taskAddr = mgr.kread64(procRO + UInt64(off_proc_ro_pr_task))
                return taskAddr != 0 ? taskAddr : nil
            }
        }

        return nil
    }

    // ── Buffer parsing helpers ────────────────────────────────────────────

    private static func parseMemlimitProps(_ buf: [UInt8]) -> (Int32, UInt32, Int32, UInt32) {
        buf.withUnsafeBytes { raw in
            let active     = raw.load(fromByteOffset: 0,  as: Int32.self)
            let activeAttr = raw.load(fromByteOffset: 4,  as: UInt32.self)
            let inactive   = raw.load(fromByteOffset: 8,  as: Int32.self)
            let inactAttr  = raw.load(fromByteOffset: 12, as: UInt32.self)
            return (active, activeAttr, inactive, inactAttr)
        }
    }

    static func buildMemlimitProps(active: Int32, activeAttr: UInt32,
                                    inactive: Int32, inactiveAttr: UInt32) -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: kMemlimitPropsSize)
        withUnsafeBytes(of: active)       { buf.replaceSubrange(0..<4,   with: $0) }
        withUnsafeBytes(of: activeAttr)   { buf.replaceSubrange(4..<8,   with: $0) }
        withUnsafeBytes(of: inactive)     { buf.replaceSubrange(8..<12,  with: $0) }
        withUnsafeBytes(of: inactiveAttr) { buf.replaceSubrange(12..<16, with: $0) }
        return buf
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Data model
// ═══════════════════════════════════════════════════════════════════════════

struct JetsamProcess: Identifiable {
    let id      = UUID()
    let pid:    UInt32
    let uid:    UInt32
    let name:   String
    var targetBand:       Int  = 12
    var limitMB:          Int  = -1      // -1 = unlimited (manual override)
    var terminateOnLimit: Bool = false   // true → hard kill at limit; false → soft warning
    var isProtected: Bool = false
    var origBand:    Int  = 10           // recorded before modification for restore

    // Multiplier state
    var multiplier:       Int  = 0      // 0 = not applied; 2/3/4 = active multiplier
    var origActiveMB:     Int  = 0      // original memlimit_active before multiplier
    var origInactiveMB:   Int  = 0      // original memlimit_inactive before multiplier
    var multiplierApproach: String = "" // which approach succeeded
}


// ═══════════════════════════════════════════════════════════════════════════
// MARK: - JetsamView
// ═══════════════════════════════════════════════════════════════════════════

struct JetsamView: View {
    @ObservedObject private var mgr = laramgr.shared

    @State private var processes:     [JetsamProcess] = []
    @State private var loading        = false
    @State private var searchText     = ""

    // Status alert
    @State private var statusMessage:  String = ""
    @State private var showStatus      = false

    // Editor sheet — keyed on pid
    @State private var editingPID:    UInt32?
    @State private var showEditor     = false

    // Confirm restore-all
    @State private var showRestoreAll = false

    // Global multiplier
    @State private var globalMultiplier: Int = 3
    @State private var showGlobalConfirm = false
    @State private var applyingGlobal    = false

    // Auto-protect timer
    @State private var autoProtectEnabled = false
    @State private var autoProtectTimer:  Timer?
    @State private var autoProtectMultiplier: Int = 3
    @State private var autoProtectCount: Int = 0    // how many processes auto-protected

    private var protectedProcesses: [JetsamProcess] {
        processes.filter { $0.isProtected || $0.multiplier > 0 }
    }

    private var filteredProcesses: [JetsamProcess] {
        let base = processes.filter { !$0.isProtected && $0.multiplier == 0 }
        guard !searchText.isEmpty else { return base }
        return base.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }

    // MARK: - Body

    var body: some View {
        List {
            // Global multiplier controls
            globalMultiplierSection

            if !protectedProcesses.isEmpty {
                protectedSection
            }
            runningSection
        }
        .listStyle(.insetGrouped)
        .searchable(text: $searchText, prompt: "Filter processes")
        .navigationTitle("Jetsam")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if !protectedProcesses.isEmpty {
                    Button("Restore All") { showRestoreAll = true }
                        .foregroundColor(.orange)
                }
                Button {
                    refresh()
                } label: {
                    if loading { ProgressView().scaleEffect(0.8) }
                    else { Image(systemName: "arrow.clockwise") }
                }
            }
        }
        .alert("Jetsam Result", isPresented: $showStatus) {
            Button("OK") { showStatus = false }
        } message: {
            Text(statusMessage)
        }
        .alert("Restore all Jetsam changes?", isPresented: $showRestoreAll) {
            Button("Restore", role: .destructive) { restoreAll() }
            Button("Cancel", role: .cancel) {}
        }
        .alert("Apply \(globalMultiplier)x to all \(processes.count) processes?",
               isPresented: $showGlobalConfirm) {
            Button("Apply", role: .destructive) { applyGlobalMultiplier() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will read each process's current jetsam memory limit and multiply it by \(globalMultiplier). Tries 5 approaches in fallback order.")
        }
        .sheet(isPresented: $showEditor) {
            if let pid = editingPID,
               let idx = processes.firstIndex(where: { $0.pid == pid }) {
                EditorSheet(process: $processes[idx],
                            onApply: { apply(pid: pid) },
                            onMultiply: { mult in applyMultiplierToProcess(pid: pid, multiplier: mult) })
            }
        }
        .onAppear { refresh() }
        .onDisappear { stopAutoProtect() }
    }

    // MARK: - Global multiplier section

    private var globalMultiplierSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Image(systemName: "bolt.shield")
                        .foregroundColor(.purple)
                    Text("Jetsam Multiplier")
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.semibold)
                    Spacer()
                    Text("Dopamine-style")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                }

                // Multiplier picker
                HStack(spacing: 8) {
                    ForEach([2, 3, 4], id: \.self) { mult in
                        Button("\(mult)x") {
                            globalMultiplier = mult
                        }
                        .font(.system(.body, design: .monospaced).bold())
                        .buttonStyle(.bordered)
                        .tint(globalMultiplier == mult ? .purple : .secondary)
                        .controlSize(.regular)
                    }

                    Spacer()

                    Button {
                        showGlobalConfirm = true
                    } label: {
                        HStack(spacing: 4) {
                            if applyingGlobal {
                                ProgressView().scaleEffect(0.7)
                            }
                            Text("Apply to All")
                                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.purple)
                    .disabled(applyingGlobal)
                }

                // Auto-protect toggle
                HStack {
                    Toggle(isOn: $autoProtectEnabled) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Auto-protect new processes")
                                .font(.system(.body, design: .monospaced))
                            Text(autoProtectEnabled
                                 ? "Scanning every 5s · \(autoProtectCount) applied"
                                 : "Watch for new processes and apply multiplier automatically")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(autoProtectEnabled ? .green : .secondary)
                        }
                    }
                    .onChange(of: autoProtectEnabled) { enabled in
                        if enabled { startAutoProtect() } else { stopAutoProtect() }
                    }
                }
            }
        } header: {
            Text("Memory Multiplier")
        } footer: {
            Text("Reads each process's current jetsam limit and multiplies it. Tries: direct → RC configd → RC any root process → syscall(440) → KRW kernel write.")
        }
    }

    // MARK: - Protected section

    private var protectedSection: some View {
        Section {
            ForEach(protectedProcesses) { proc in
                HStack(spacing: 10) {
                    Circle().fill(proc.multiplier > 0 ? Color.purple : Color.green)
                        .frame(width: 8, height: 8)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(proc.name)
                            .font(.system(.body, design: .monospaced))
                            .fontWeight(.semibold)
                        HStack(spacing: 6) {
                            if proc.multiplier > 0 {
                                bandTag("\(proc.multiplier)x", .purple)
                                Text("\(proc.origActiveMB)→\(proc.origActiveMB * proc.multiplier) MB")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.secondary)
                                if !proc.multiplierApproach.isEmpty {
                                    bandTag(proc.multiplierApproach, .indigo)
                                }
                            }
                            if proc.isProtected {
                                Text("band \(proc.origBand)→\(proc.targetBand)")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                            if proc.limitMB == -1 && proc.multiplier == 0 {
                                bandTag("unlimited", .blue)
                            } else if proc.limitMB > 0 && proc.multiplier == 0 {
                                bandTag("\(proc.limitMB) MB \(proc.terminateOnLimit ? "hard" : "soft")", .orange)
                            }
                        }
                    }
                    Spacer()
                    Text("pid \(proc.pid)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                    Button("Restore") {
                        restore(pid: Int32(proc.pid))
                    }
                    .font(.system(size: 12))
                    .buttonStyle(.bordered)
                    .tint(.orange)
                }
                .padding(.vertical, 2)
            }
        } header: {
            Text("Protected (\(protectedProcesses.count))")
        } footer: {
            Text("Restore before rebooting to avoid unexpected behaviour.")
                .foregroundColor(.orange)
        }
    }

    // MARK: - Running processes section

    private var runningSection: some View {
        Section {
            if loading {
                HStack { Spacer(); ProgressView(); Text("Scanning…").foregroundColor(.secondary); Spacer() }
            } else if filteredProcesses.isEmpty {
                Text(searchText.isEmpty ? "No processes found" : "No matches")
                    .foregroundColor(.secondary)
            } else {
                ForEach(filteredProcesses.indices, id: \.self) { i in
                    processRow(filteredProcesses[i])
                }
            }
        } header: {
            HStack {
                Text(searchText.isEmpty
                     ? "Running (\(processes.count))"
                     : "Running (\(filteredProcesses.count) of \(processes.count))")
                Spacer()
                Text("R = root  M = mobile")
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.secondary)
            }
        } footer: {
            Text("Tap a process to set its Jetsam priority band, memory limit, or multiplier.")
        }
    }

    @ViewBuilder
    private func processRow(_ proc: JetsamProcess) -> some View {
        HStack(spacing: 10) {
            Text(proc.uid == 0 ? "R" : "M")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(proc.uid == 0 ? .orange : .secondary)
                .frame(width: 14)

            VStack(alignment: .leading, spacing: 1) {
                Text(proc.name)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                Text("pid \(proc.pid)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary)
            }

            Spacer()

            Image(systemName: "cpu")
                .foregroundColor(.secondary)
        }
        .contentShape(Rectangle())
        .onTapGesture {
            editingPID = proc.pid
            showEditor = true
        }
        .disabled(!mgr.dsready && !mgr.sbxready)
    }

    // MARK: - Editor sheet

    struct EditorSheet: View {
        @Binding var process: JetsamProcess
        let onApply: () -> Void
        let onMultiply: (Int) -> Void
        @Environment(\.dismiss) private var dismiss

        @State private var bandDouble:       Double = 12
        @State private var limitDouble:      Double = -1
        @State private var terminateOnLimit: Bool   = false
        @State private var selectedMultiplier: Int  = 3
        @State private var multiplyBusy:     Bool   = false

        private let bandMarkers: [(Int, String)] = [
            (0,  "idle"), (4, "bg suspend"), (5, "bg audio"),
            (8,  "daemon"), (10, "foreground"), (12, "assertion"),
            (15, "SpringBoard"), (16, "critical — max safe")
        ]

        var body: some View {
            NavigationView {
                List {
                    Section("Process") {
                        LabeledContent("Name", value: process.name)
                        LabeledContent("PID",  value: "\(process.pid)")
                        LabeledContent("UID",  value: "\(process.uid) (\(process.uid == 0 ? "root" : "mobile"))")
                    }

                    // ── Multiplier section (Dopamine-style) ───────────────────
                    Section {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                Image(systemName: "bolt.shield")
                                    .foregroundColor(.purple)
                                Text("Memory Multiplier")
                                    .font(.system(.body, design: .monospaced))
                                Spacer()
                                if process.multiplier > 0 {
                                    bandTag("active: \(process.multiplier)x", .purple)
                                }
                            }

                            HStack(spacing: 8) {
                                ForEach([2, 3, 4], id: \.self) { mult in
                                    Button("\(mult)x") {
                                        selectedMultiplier = mult
                                    }
                                    .font(.system(.body, design: .monospaced).bold())
                                    .buttonStyle(.bordered)
                                    .tint(selectedMultiplier == mult ? .purple : .secondary)
                                }
                            }

                            Button {
                                multiplyBusy = true
                                onMultiply(selectedMultiplier)
                                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                                    multiplyBusy = false
                                }
                            } label: {
                                HStack {
                                    Spacer()
                                    if multiplyBusy {
                                        ProgressView().scaleEffect(0.8)
                                    } else {
                                        Label("Apply \(selectedMultiplier)x Multiplier", systemImage: "bolt.shield.fill")
                                    }
                                    Spacer()
                                }
                                .fontWeight(.semibold)
                            }
                            .foregroundColor(.white)
                            .listRowBackground(Color.purple.opacity(0.85))
                            .disabled(multiplyBusy)
                        }
                    } header: { Text("Jetsam Multiplier") }
                    footer: { Text("Reads the current memory limit and multiplies it. Tries 5 different approaches in fallback order.") }

                    // ── Priority band ─────────────────────────────────────────
                    Section {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                Text("Band")
                                    .font(.system(.body, design: .monospaced))
                                Spacer()
                                Text("\(Int(bandDouble))  · \(bandLabel(Int(bandDouble)))")
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundColor(bandColour(Int(bandDouble)))
                                    .fontWeight(.semibold)
                            }
                            Slider(value: $bandDouble, in: 0...16, step: 1)
                                .tint(bandColour(Int(bandDouble)))
                            ScrollView(.horizontal, showsIndicators: false) {
                                HStack(spacing: 6) {
                                    ForEach(bandMarkers, id: \.0) { band, label in
                                        Button("\(band)") { bandDouble = Double(band) }
                                            .font(.system(size: 10, design: .monospaced))
                                            .buttonStyle(.bordered)
                                            .tint(Int(bandDouble) == band ? bandColour(band) : .secondary)
                                            .controlSize(.mini)
                                    }
                                }
                            }
                        }
                    } header: { Text("Priority Band") }
                    footer: { Text("Foreground apps sit at band 10. SpringBoard is 15. Do not exceed 16.") }

                    // ── Memory limit ──────────────────────────────────────────
                    Section {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                Text("Memory Limit")
                                    .font(.system(.body, design: .monospaced))
                                Spacer()
                                Text(limitDouble < 0 ? "Unlimited" : "\(Int(limitDouble)) MB")
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundColor(limitDouble < 0 ? .blue : .orange)
                                    .fontWeight(.semibold)
                            }
                            Slider(value: $limitDouble, in: -1...2048, step: 1)
                                .tint(limitDouble < 0 ? .blue : .orange)
                            Toggle("Unlimited (no cap)", isOn: Binding(
                                get: { limitDouble < 0 },
                                set: { limitDouble = $0 ? -1 : 512 }
                            ))
                            Divider()
                            Toggle(isOn: $terminateOnLimit) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Terminate process on limit reached")
                                        .font(.system(.body, design: .monospaced))
                                    Text(terminateOnLimit
                                         ? "Hard cap — process is killed when footprint exceeds limit"
                                         : "Soft cap — process receives a jetsam warning, not killed")
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundColor(terminateOnLimit ? .red : .secondary)
                                }
                            }
                            .disabled(limitDouble < 0)
                        }
                    } header: { Text("Memory Limit") }
                    footer: { Text("Unlimited removes the per-process footprint cap. A specific limit caps a runaway process.") }

                    // ── Apply band + limit button ─────────────────────────────
                    Section {
                        Button {
                            process.targetBand       = Int(bandDouble)
                            process.limitMB          = Int(limitDouble)
                            process.terminateOnLimit = terminateOnLimit
                            onApply()
                            dismiss()
                        } label: {
                            HStack {
                                Spacer()
                                Label("Apply Jetsam Policy", systemImage: "cpu")
                                    .fontWeight(.semibold)
                                Spacer()
                            }
                        }
                        .foregroundColor(.white)
                        .listRowBackground(Color.blue)
                    }
                }
                .listStyle(.insetGrouped)
                .navigationTitle(process.name)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }
                    }
                }
                .onAppear {
                    bandDouble       = Double(process.targetBand)
                    limitDouble      = Double(process.limitMB)
                    terminateOnLimit = process.terminateOnLimit
                    selectedMultiplier = process.multiplier > 0 ? process.multiplier : 3
                }
            }
        }

        private func bandLabel(_ b: Int) -> String {
            bandMarkers.last(where: { $0.0 <= b })?.1 ?? "?"
        }

        private func bandColour(_ b: Int) -> Color {
            switch b {
            case 0...4:   return .red
            case 5...9:   return .orange
            case 10...12: return .green
            case 13...15: return .blue
            default:      return .purple
            }
        }

        @ViewBuilder
        private func bandTag(_ text: String, _ color: Color) -> some View {
            Text(text)
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .foregroundColor(color)
                .padding(.horizontal, 4).padding(.vertical, 2)
                .background(
                    RoundedRectangle(cornerRadius: 3)
                        .fill(color.opacity(0.12))
                        .overlay(RoundedRectangle(cornerRadius: 3).stroke(color.opacity(0.3), lineWidth: 0.5))
                )
        }
    }

    // MARK: - Multiplier actions

    /// Apply the multiplier to a single process (called from EditorSheet)
    private func applyMultiplierToProcess(pid: UInt32, multiplier: Int) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = JetsamMultiplier.applyMultiplier(
                pid: Int32(pid), multiplier: Int32(multiplier)
            )

            DispatchQueue.main.async {
                if let idx = processes.firstIndex(where: { $0.pid == pid }) {
                    if result.ok {
                        processes[idx].multiplier        = multiplier
                        processes[idx].origActiveMB      = Int(result.prevActive)
                        processes[idx].origInactiveMB    = Int(result.prevInactive)
                        processes[idx].multiplierApproach = result.approach
                    }
                }
                statusMessage = "\(result.summary)"
                showStatus    = true
            }
        }
    }

    /// Apply the global multiplier to all processes
    private func applyGlobalMultiplier() {
        applyingGlobal = true
        let mult   = globalMultiplier
        let procs  = processes

        DispatchQueue.global(qos: .userInitiated).async {
            var succeeded = 0
            var failed    = 0
            var details:  [String] = []

            for proc in procs {
                // Skip kernel (pid 0), launchd (pid 1), and already-multiplied
                guard proc.pid > 1, proc.multiplier == 0 else { continue }

                let result = JetsamMultiplier.applyMultiplier(
                    pid: Int32(proc.pid), multiplier: Int32(mult)
                )

                DispatchQueue.main.async {
                    if let idx = self.processes.firstIndex(where: { $0.pid == proc.pid }), result.ok {
                        self.processes[idx].multiplier        = mult
                        self.processes[idx].origActiveMB      = Int(result.prevActive)
                        self.processes[idx].origInactiveMB    = Int(result.prevInactive)
                        self.processes[idx].multiplierApproach = result.approach
                    }
                }

                if result.ok { succeeded += 1 }
                else {
                    failed += 1
                    details.append("\(proc.name): \(result.detail)")
                }
            }

            DispatchQueue.main.async {
                self.applyingGlobal = false
                self.statusMessage  = "\(mult)x applied to \(succeeded) processes"
                    + (failed > 0 ? ", \(failed) failed" : "")
                    + (details.isEmpty ? "" : "\n" + details.prefix(5).joined(separator: "\n"))
                self.showStatus     = true
            }
        }
    }

    // MARK: - Auto-protect

    private func startAutoProtect() {
        stopAutoProtect()
        autoProtectCount = 0
        autoProtectTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
            autoProtectTick()
        }
    }

    private func stopAutoProtect() {
        autoProtectTimer?.invalidate()
        autoProtectTimer = nil
    }

    /// Called every 5s when auto-protect is on.  Scans proclist for new processes
    /// (those not in our current `processes` array or not yet multiplied) and
    /// applies the multiplier.
    private func autoProtectTick() {
        let mult = globalMultiplier
        let knownPIDs = Set(processes.filter { $0.multiplier > 0 }.map { $0.pid })

        DispatchQueue.global(qos: .utility).async {
            var count: Int32 = 0
            guard let ptr = proclist(nil, &count), count > 0 else { return }
            defer { free_proclist(ptr) }

            var newlyProtected = 0

            for i in 0..<Int(count) {
                let e = ptr[i]
                guard e.pid > 1, !knownPIDs.contains(e.pid) else { continue }

                let result = JetsamMultiplier.applyMultiplier(
                    pid: Int32(e.pid), multiplier: Int32(mult)
                )

                if result.ok {
                    newlyProtected += 1
                    let name = withUnsafeBytes(of: e.name) { raw -> String in
                        let b   = raw.bindMemory(to: UInt8.self)
                        let end = b.firstIndex(of: 0) ?? b.endIndex
                        return String(bytes: b[..<end], encoding: .utf8) ?? "pid \(e.pid)"
                    }

                    DispatchQueue.main.async {
                        // Add or update in processes array
                        if let idx = self.processes.firstIndex(where: { $0.pid == e.pid }) {
                            self.processes[idx].multiplier        = mult
                            self.processes[idx].origActiveMB      = Int(result.prevActive)
                            self.processes[idx].origInactiveMB    = Int(result.prevInactive)
                            self.processes[idx].multiplierApproach = result.approach
                        } else {
                            var p = JetsamProcess(pid: e.pid, uid: e.uid, name: name)
                            p.multiplier        = mult
                            p.origActiveMB      = Int(result.prevActive)
                            p.origInactiveMB    = Int(result.prevInactive)
                            p.multiplierApproach = result.approach
                            self.processes.append(p)
                        }
                    }
                }
            }

            if newlyProtected > 0 {
                DispatchQueue.main.async {
                    self.autoProtectCount += newlyProtected
                }
            }
        }
    }

    // MARK: - Band/limit actions (existing)

    private func refresh() {
        guard !loading else { return }
        loading = true
        DispatchQueue.global(qos: .userInitiated).async {
            var result: [JetsamProcess] = []
            var count: Int32 = 0
            if let ptr = proclist(nil, &count), count > 0 {
                for i in 0..<Int(count) {
                    let e = ptr[i]
                    guard e.pid > 1 else { continue }
                    let name = withUnsafeBytes(of: e.name) { raw -> String in
                        let b   = raw.bindMemory(to: UInt8.self)
                        let end = b.firstIndex(of: 0) ?? b.endIndex
                        return String(bytes: b[..<end], encoding: .utf8) ?? "?"
                    }
                    guard !name.isEmpty else { continue }
                    let existing = self.processes.first(where: { $0.pid == e.pid })
                    var p = JetsamProcess(pid: e.pid, uid: e.uid, name: name)
                    if let ex = existing {
                        // Preserve all protected/multiplier state
                        if ex.isProtected || ex.multiplier > 0 {
                            p.isProtected        = ex.isProtected
                            p.targetBand         = ex.targetBand
                            p.limitMB            = ex.limitMB
                            p.origBand           = ex.origBand
                            p.multiplier         = ex.multiplier
                            p.origActiveMB       = ex.origActiveMB
                            p.origInactiveMB     = ex.origInactiveMB
                            p.multiplierApproach = ex.multiplierApproach
                            p.terminateOnLimit   = ex.terminateOnLimit
                        }
                    }
                    result.append(p)
                }
                free_proclist(ptr)
            }
            DispatchQueue.main.async {
                self.processes = result.sorted { $0.name.lowercased() < $1.name.lowercased() }
                self.loading   = false
            }
        }
    }

    private func apply(pid: UInt32) {
        guard let idx = processes.firstIndex(where: { $0.pid == pid }) else { return }
        let proc    = processes[idx]
        let band    = Int32(proc.targetBand)
        let limitMB = Int32(proc.limitMB)

        // Set priority band
        let bandOK = setJetsamBand(pid: Int32(proc.pid), band: band)

        // Set memory limit
        var limitOK = true
        if limitMB > 0 {
            let flags: UInt32 = UInt32(limitMB) | (proc.terminateOnLimit ? MEMORYSTATUS_FLAGS_HWM_HARD : 0)
            let ret = memorystatus_control(
                MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK,
                Int32(proc.pid),
                flags,
                nil,
                0
            )
            limitOK = ret == 0
        }

        processes[idx].isProtected = bandOK
        processes[idx].origBand    = bandOK ? proc.origBand : proc.origBand

        let limitDesc: String
        if limitMB == -1 {
            limitDesc = ", memory: system default"
        } else if limitMB > 0 {
            limitDesc = ", \(limitMB) MB (\(proc.terminateOnLimit ? "hard kill" : "soft warn")) \(limitOK ? "✓" : "⚠ failed")"
        } else {
            limitDesc = ""
        }

        if bandOK {
            statusMessage = "Protected \(proc.name) → band \(band)\(limitDesc)"
        } else {
            statusMessage = "memorystatus_control failed for \(proc.name) (pid \(proc.pid)) — sbx escape may be required"
        }
        showStatus = true
    }

    private func restore(pid: Int32) {
        guard let idx = processes.firstIndex(where: { $0.pid == UInt32(pid) }) else { return }
        let proc = processes[idx]

        // Restore band if it was changed
        if proc.isProtected {
            _ = setJetsamBand(pid: pid, band: Int32(proc.origBand))
        }

        // Restore multiplier: write back original limits
        if proc.multiplier > 0 && proc.origActiveMB > 0 {
            // Try to restore via the same mechanism
            var restoreBuf = JetsamMultiplier.buildMemlimitProps(
                active: Int32(proc.origActiveMB), activeAttr: 0,
                inactive: Int32(proc.origInactiveMB), inactiveAttr: 0
            )
            _ = restoreBuf.withUnsafeMutableBytes { ptr in
                memorystatus_control(
                    MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES,
                    pid,
                    0,
                    ptr.baseAddress,
                    kMemlimitPropsSize
                )
            }
        }

        processes[idx].isProtected        = false
        processes[idx].multiplier         = 0
        processes[idx].multiplierApproach = ""
        statusMessage = "Restored \(proc.name) to original state"
        showStatus    = true
    }

    private func restoreAll() {
        for proc in protectedProcesses {
            restore(pid: Int32(proc.pid))
        }
        statusMessage = "All Jetsam changes restored"
        showStatus    = true
    }

    // MARK: - memorystatus_control wrapper

    private func setJetsamBand(pid: Int32, band: Int32) -> Bool {
        // memorystatus_priority_properties_t:
        //   int32_t  priority   (offset 0)
        //   uint64_t user_data  (offset 8, natural alignment)
        // Total: 16 bytes
        var buf = [UInt8](repeating: 0, count: 16)
        withUnsafeBytes(of: band) { src in
            buf.replaceSubrange(0..<4, with: src)
        }
        let ret = buf.withUnsafeMutableBytes { ptr in
            memorystatus_control(
                MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES,
                pid,
                0,
                ptr.baseAddress,
                16
            )
        }
        return ret == 0
    }

    // MARK: - Band helpers

    private func bandColour(_ b: Int) -> Color {
        switch b {
        case 0...4:   return .red
        case 5...9:   return .orange
        case 10...12: return .green
        case 13...15: return .blue
        default:      return .purple
        }
    }

    @ViewBuilder
    private func bandTag(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .semibold, design: .monospaced))
            .foregroundColor(color)
            .padding(.horizontal, 4).padding(.vertical, 2)
            .background(
                RoundedRectangle(cornerRadius: 3)
                    .fill(color.opacity(0.12))
                    .overlay(RoundedRectangle(cornerRadius: 3).stroke(color.opacity(0.3), lineWidth: 0.5))
            )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - End of JetsamView
// ═══════════════════════════════════════════════════════════════════════════
