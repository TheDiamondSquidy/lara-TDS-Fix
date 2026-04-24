// ═══════════════════════════════════════════════════════════════════════════
// JETSAM KRW OFFSETS — ADD THESE TO YOUR EXISTING FILES
// ═══════════════════════════════════════════════════════════════════════════
//
// The KRW approach (Approach 5) in JetsamView.swift needs kernel task struct
// offsets to read/write memlimit fields directly.  The other 4 approaches
// work without these — KRW is only the last-resort fallback.
//
// ─── How to find these offsets ────────────────────────────────────────────
//
//   Option A: XNU source (if your version is open-sourced)
//     1. Open osfmk/kern/task.h
//     2. Find `struct task { ... }`
//     3. Locate fields:
//          int32_t   task_jetsam_priority
//          int32_t   task_memlimit_active       (MB)
//          int32_t   task_memlimit_inactive      (MB)
//          uint32_t  task_memlimit_active_attr
//          uint32_t  task_memlimit_inactive_attr
//     4. Calculate offsets from the start of struct task
//
//   Option B: IDA/Ghidra (any version)
//     1. Find memorystatus_set_memlimit_properties_internal()
//     2. It writes to task+N for memlimit_active and task+M for memlimit_inactive
//     3. Those N and M are your offsets
//     4. The attr fields are at +4 from each limit field
//
//   Option C: Dynamic scanning
//     1. Get a known task address (e.g. lara's own task via proc→proc_ro→task)
//     2. Set a known jetsam limit via memorystatus_control (e.g. 999 MB)
//     3. Scan the task struct region for the value 999 (0x3E7)
//     4. That byte offset is off_task_memlimit_active
//     5. Repeat for inactive with a different value
//

// ═══════════════════════════════════════════════════════════════════════════
// ADD TO: offsets.h (inside the extern "C" block)
// ═══════════════════════════════════════════════════════════════════════════

/*
extern uint32_t off_task_jetsam_priority;
extern uint32_t off_task_memlimit_active;
extern uint32_t off_task_memlimit_inactive;
extern uint32_t off_task_memlimit_active_attr;
extern uint32_t off_task_memlimit_inactive_attr;
*/


// ═══════════════════════════════════════════════════════════════════════════
// ADD TO: offsets.m (inside offsets_init() or wherever offsets are resolved)
// ═══════════════════════════════════════════════════════════════════════════

/*
uint32_t off_task_jetsam_priority       = 0;
uint32_t off_task_memlimit_active       = 0;
uint32_t off_task_memlimit_inactive     = 0;
uint32_t off_task_memlimit_active_attr  = 0;
uint32_t off_task_memlimit_inactive_attr= 0;

// Inside offsets_init():
// ─── Example values (VERIFY FOR YOUR TARGET) ─────────────────────────
// These are approximate offsets from iOS 16.x A12+ kernelcache.
// They WILL differ across iOS versions and chip families.
//
// off_task_jetsam_priority       = 0x3A0;   // verify
// off_task_memlimit_active       = 0x3A4;   // verify
// off_task_memlimit_inactive     = 0x3A8;   // verify
// off_task_memlimit_active_attr  = 0x3AC;   // verify
// off_task_memlimit_inactive_attr= 0x3B0;   // verify
*/


// ═══════════════════════════════════════════════════════════════════════════
// THEN IN JetsamView.swift — replace the placeholder lines:
// ═══════════════════════════════════════════════════════════════════════════

/*
// Change FROM:
private var off_task_jetsam_priority:       UInt64 = 0x0
private var off_task_memlimit_active:       UInt64 = 0x0
private var off_task_memlimit_inactive:     UInt64 = 0x0
private var off_task_memlimit_active_attr:  UInt64 = 0x0
private var off_task_memlimit_inactive_attr:UInt64 = 0x0

// Change TO (reads from the C globals set in offsets_init):
private var off_task_jetsam_priority:       UInt64 { UInt64(lara.off_task_jetsam_priority) }
private var off_task_memlimit_active:       UInt64 { UInt64(lara.off_task_memlimit_active) }
private var off_task_memlimit_inactive:     UInt64 { UInt64(lara.off_task_memlimit_inactive) }
private var off_task_memlimit_active_attr:  UInt64 { UInt64(lara.off_task_memlimit_active_attr) }
private var off_task_memlimit_inactive_attr:UInt64 { UInt64(lara.off_task_memlimit_inactive_attr) }
*/


// ═══════════════════════════════════════════════════════════════════════════
// DYNAMIC OFFSET SCANNER (optional — add to JetsamMultiplier if desired)
// ═══════════════════════════════════════════════════════════════════════════
//
// This function can auto-detect memlimit offsets at runtime by:
//   1. Setting lara's own jetsam limit to a known canary value via memorystatus_control
//   2. Reading through lara's task struct looking for that canary
//   3. Recording the offset
//   4. Restoring the original limit
//
// This eliminates the need to hardcode offsets per iOS version.

/*
static func scanForMemlimitOffsets() -> (active: UInt64, inactive: UInt64)? {
    let mgr = laramgr.shared
    guard mgr.dsready else { return nil }
    
    let myPid = getpid()
    
    // Read current limits so we can restore them
    var origBuf = [UInt8](repeating: 0, count: kMemlimitPropsSize)
    let getRet = origBuf.withUnsafeMutableBytes { ptr in
        memorystatus_control(8, myPid, 0, ptr.baseAddress, kMemlimitPropsSize)
    }
    guard getRet == 0 else { return nil }
    
    // Set active limit to canary value 0xBEEF (48879 MB — absurd but unique)
    let canary: Int32 = 0x0000BEEF
    var setBuf = JetsamMultiplier.buildMemlimitProps(
        active: canary, activeAttr: 0, inactive: canary + 1, inactiveAttr: 0
    )
    _ = setBuf.withUnsafeMutableBytes { ptr in
        memorystatus_control(7, myPid, 0, ptr.baseAddress, kMemlimitPropsSize)
    }
    
    // Find our task addr
    guard let taskAddr = resolveTaskAddr(forPid: myPid) else {
        // Restore
        _ = origBuf.withUnsafeMutableBytes { ptr in
            memorystatus_control(7, myPid, 0, ptr.baseAddress, kMemlimitPropsSize)
        }
        return nil
    }
    
    // Scan task struct (first 0x600 bytes should be enough)
    var activeOff:   UInt64 = 0
    var inactiveOff: UInt64 = 0
    
    for offset in stride(from: UInt64(0), to: UInt64(0x600), by: 4) {
        let val = Int32(bitPattern: mgr.kcread32(taskAddr + offset))
        if val == canary && activeOff == 0 {
            activeOff = offset
        } else if val == canary + 1 && inactiveOff == 0 {
            inactiveOff = offset
        }
        if activeOff != 0 && inactiveOff != 0 { break }
    }
    
    // Restore original limits
    _ = origBuf.withUnsafeMutableBytes { ptr in
        memorystatus_control(7, myPid, 0, ptr.baseAddress, kMemlimitPropsSize)
    }
    
    guard activeOff != 0, inactiveOff != 0 else { return nil }
    
    // Store globally
    off_task_memlimit_active   = activeOff
    off_task_memlimit_inactive = inactiveOff
    off_task_memlimit_active_attr  = activeOff + 4
    off_task_memlimit_inactive_attr = inactiveOff + 4
    
    return (activeOff, inactiveOff)
}
*/
