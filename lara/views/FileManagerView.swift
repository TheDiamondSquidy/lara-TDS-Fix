//
//  RemoteFileIO.swift
//  lara — TDS fork
//
//  RemoteCall-backed file I/O engine.
//
//  Process pool and routing:
//    mobile_backup_agent2  mobile + backup entitlement  (widest /var/mobile reach; iOS 17+)
//    mobile_backup_agent   mobile + backup entitlement  (iOS ≤16)
//    SpringBoard           mobile uid                   (default /var/mobile/**)
//    configd               root uid                     (/var/db/*, /var/root/*)
//    mobileidentityd       MobileIdentityData MAC label (spawned on demand)
//    securityd             Keychains MAC label
//    dataaccessd           DPLA / DataAccess            (spawned on demand)
//    mediaserverd          Media library paths
//
//  Fallback chain per operation:
//    1. Direct I/O (post-sbx-escape)  — fastest, works when SBX grants access
//    2. VFS overwrite (existing inodes only)
//    3. override process (if set by user — "Isolate" in ProcessSelectorView)
//    4. routed process (best match for path)
//    5. all other currently-ready pool processes
//    6. fail with full diagnostic
//
//  Directory listing chain (VFS/SBX first per user spec):
//    1. VFS listdir           — SBX/VFS layer, same as Lara FM
//    2. FileManager (post-sbx) — direct IO
//    3. RC opendir/readdir    — privilege-escalated, reaches protected dirs
//    4. empty + "failed"
//
//  Known iOS version differences:
//    iOS ≤16:  backup daemon = "mobile_backup_agent"
//    iOS 17+:  backup daemon = "mobile_backup_agent2"
//

import Foundation
import Combine
import Darwin

// MARK: - Diagnostics types

/// Tier that ultimately succeeded (or the last attempted before failure)
enum RCIOTier: String, CustomStringConvertible {
    case direct     = "direct"
    case vfs        = "vfs"
    case remoteCall = "remotecall"
    case failed     = "failed"
    var description: String { rawValue }
}

/// Full result of a single read or write operation
struct RCIOResult {
    let ok:         Bool
    let tier:       RCIOTier
    let process:    String?
    let bytes:      Int
    let duration:   TimeInterval
    let message:    String
    let diagnostic: String

    static func failure(_ msg: String, diagnostic: String = "", duration: TimeInterval = 0) -> RCIOResult {
        RCIOResult(ok: false, tier: .failed, process: nil, bytes: 0,
                   duration: duration, message: msg, diagnostic: diagnostic)
    }
}

/// Single entry in the operation log
struct RCIOLogEntry: Identifiable {
    let id        = UUID()
    let timestamp: Date
    let operation: String       // "read" / "write" / "delete" / "move" / "mkdir" / "listdir"
    let path:      String
    let result:    RCIOResult

    var summary: String {
        let ts = DateFormatter.localizedString(from: timestamp, dateStyle: .none, timeStyle: .medium)
        return "[\(ts)] \(result.ok ? "✓" : "✗") \(operation) \(URL(fileURLWithPath: path).lastPathComponent) — \(result.message)"
    }
}

// MARK: - Pool entry

struct RCPoolEntry {
    enum State: CustomStringConvertible {
        case uninitialized
        case initializing
        case spawning               // launchctl kickstart in progress
        case ready(pid: Int32)
        case failed(reason: String)

        var description: String {
            switch self {
            case .uninitialized:        return "uninitialized"
            case .initializing:         return "initializing..."
            case .spawning:             return "spawning..."
            case .ready(let pid):       return "ready (pid \(pid))"
            case .failed(let reason):   return "failed: \(reason)"
            }
        }

        var isReady: Bool {
            if case .ready = self { return true }
            return false
        }
    }

    let process: String
    var state:   State
    var rc:      RemoteCall?
}

// MARK: - Running process info

struct RunningProcess: Identifiable {
    let id   = UUID()
    let pid:  UInt32
    let uid:  UInt32
    let name: String
    var isRoot: Bool { uid == 0 }
}

// MARK: - Bookmark model

struct RCBookmark: Identifiable, Codable, Equatable {
    var id: UUID = UUID()
    let path: String
    let label: String
    let createdAt: Date

    var displayName: String {
        label.isEmpty ? URL(fileURLWithPath: path).lastPathComponent : label
    }
}

// MARK: - RemoteFileIO

final class RemoteFileIO: ObservableObject {

    static let shared = RemoteFileIO()

    // Published state
    @Published private(set) var pool: [String: RCPoolEntry] = [:]
    @Published private(set) var log:  [RCIOLogEntry] = []
    @Published var bookmarks: [RCBookmark] = []

    private let mgr      = laramgr.shared
    private let poolLock  = NSLock()

    // UserDefaults key for bookmarks
    private static let bookmarksKey = "rcfm_bookmarks"

    // MARK: - iOS version–aware process names

    /// Returns the correct backup agent process name for the running iOS version.
    static var backupDaemonName: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return v.majorVersion >= 17 ? "mobile_backup_agent2" : "mobile_backup_agent"
    }

    // MARK: - Pool configuration

    /// Ordered list shown in ProcessSelectorView (most privileged first).
    static var recommendedProcesses: [String] {
        [
            backupDaemonName,   // widest /var/mobile write surface
            "SpringBoard",
            "configd",
            "mobileidentityd",
            "securityd",
            "dataaccessd",
            "mediaserverd",
        ]
    }

    /// Processes that must be running before RC init — kickstart them if absent.
    private static var spawnNeeded: Set<String> {
        [backupDaemonName, "mobileidentityd", "dataaccessd"]
    }

    /// launchd service labels for kickstart.
    private static var launchdServices: [String: String] {
        [
            backupDaemonName:    "com.apple.mobile.mobile_backup_agent2",
            "mobileidentityd":   "com.apple.mobileidentityd",
            "dataaccessd":       "com.apple.dataaccessd",
        ]
    }

    private init() {
        for p in Self.recommendedProcesses {
            pool[p] = RCPoolEntry(process: p, state: .uninitialized, rc: nil)
        }
        loadBookmarks()
        dbg("pool initialised with \(pool.count) slots: \(Self.recommendedProcesses.joined(separator: ", "))")
    }

    // MARK: - Debug logging

    /// Verbose debug log — always goes to the global logger and mgr.log.
    /// Every file I/O event, RC init, spawn, failure should funnel through here.
    private func dbg(_ msg: String) {
        let tagged = "(rcio) \(msg)"
        mgr.logmsg(tagged)
    }

    // MARK: - Bookmarks

    func addBookmark(path: String, label: String = "") {
        let bm = RCBookmark(path: path, label: label, createdAt: Date())
        // Don't duplicate
        guard !bookmarks.contains(where: { $0.path == path }) else {
            dbg("bookmark already exists for \(path)")
            return
        }
        bookmarks.append(bm)
        saveBookmarks()
        dbg("bookmark added: \(bm.displayName) → \(path)")
    }

    func removeBookmark(_ bookmark: RCBookmark) {
        bookmarks.removeAll { $0.id == bookmark.id }
        saveBookmarks()
        dbg("bookmark removed: \(bookmark.displayName)")
    }

    func removeBookmark(at offsets: IndexSet) {
        let removing = offsets.map { bookmarks[$0] }
        bookmarks.remove(atOffsets: offsets)
        saveBookmarks()
        for bm in removing { dbg("bookmark removed: \(bm.displayName)") }
    }

    private func saveBookmarks() {
        if let data = try? JSONEncoder().encode(bookmarks) {
            UserDefaults.standard.set(data, forKey: Self.bookmarksKey)
        }
    }

    private func loadBookmarks() {
        guard let data = UserDefaults.standard.data(forKey: Self.bookmarksKey),
              let saved = try? JSONDecoder().decode([RCBookmark].self, from: data)
        else { return }
        bookmarks = saved
    }

    // MARK: - Pool management

    /// Returns a ready RC for `process`.
    /// If the process needs spawning and isn't running, kicks it via launchctl first.
    /// Always call from a background queue — init can take several seconds.
    func rcProc(for process: String, spawnIfNeeded: Bool = true) -> RemoteCall? {
        poolLock.lock()
        let entry = pool[process]
        poolLock.unlock()

        if let rc = entry?.rc, entry?.state.isReady == true { return rc }
        if case .failed = entry?.state { return nil }

        guard mgr.dsready else {
            markFailed(process: process, reason: "darksword not ready — run the exploit first")
            return nil
        }

        // Check if process is running; spawn if needed and allowed
        if spawnIfNeeded, Self.spawnNeeded.contains(process), !isRunning(process) {
            dbg("\(process) not running — attempting kickstart spawn")
            markPoolState(process, .spawning)
            let ok = kickstart(service: process)
            if !ok {
                markFailed(process: process, reason: "kickstart failed — check Logs tab for details")
                return nil
            }
            // Wait up to 4s for the daemon to appear
            var appeared = false
            for attempt in 1...8 {
                Thread.sleep(forTimeInterval: 0.5)
                if isRunning(process) {
                    appeared = true
                    dbg("\(process) appeared after \(attempt * 500)ms")
                    break
                }
            }
            guard appeared else {
                markFailed(process: process, reason: "daemon did not appear within 4s after kickstart")
                return nil
            }
        } else if !Self.spawnNeeded.contains(process), !isRunning(process) {
            markFailed(process: process, reason: "process '\(process)' is not running; use Spawn to start it")
            return nil
        }

        markPoolState(process, .initializing)
        dbg("RC init starting for \(process)...")

        guard let rc = RemoteCall(process: process, useMigFilterBypass: false) else {
            markFailed(process: process, reason: "RemoteCall init returned nil — process may have exited")
            return nil
        }

        let pid = Int32(truncatingIfNeeded: callIn(rc: rc, name: "getpid", args: []))

        poolLock.lock()
        pool[process] = RCPoolEntry(process: process, state: .ready(pid: pid), rc: rc)
        poolLock.unlock()
        publish()
        dbg("ready: \(process) pid=\(pid)")
        return rc
    }

    func destroyProc(_ process: String) {
        poolLock.lock()
        let old = pool[process]
        pool[process] = RCPoolEntry(process: process, state: .uninitialized, rc: nil)
        poolLock.unlock()
        old?.rc?.destroy()
        publish()
        dbg("destroyed RC session for \(process)")
    }

    func resetProc(_ process: String) {
        poolLock.lock()
        if case .failed = pool[process]?.state {
            pool[process] = RCPoolEntry(process: process, state: .uninitialized, rc: nil)
        }
        poolLock.unlock()
        publish()
        dbg("reset \(process) to uninitialized")
    }

    /// Add an arbitrary (non-recommended) process to the pool.
    func addArbitraryProcess(_ name: String) {
        poolLock.lock()
        if pool[name] == nil {
            pool[name] = RCPoolEntry(process: name, state: .uninitialized, rc: nil)
        }
        poolLock.unlock()
        publish()
        dbg("added arbitrary process to pool: \(name)")
    }

    // MARK: - Spawn / kickstart

    /// Spawns a launchd service by running `launchctl kickstart` inside SpringBoard's RC session.
    /// Tries the system domain first, then the user/501 domain.
    @discardableResult
    func kickstart(service: String) -> Bool {
        let serviceLabel = Self.launchdServices[service] ?? service
        dbg("kickstart requested for \(service) (label: \(serviceLabel))")

        // SpringBoard must be RC-ready to host the posix_spawn.
        poolLock.lock()
        let sbEntry = pool["SpringBoard"]
        poolLock.unlock()
        guard case .ready = sbEntry?.state, let rc = sbEntry?.rc else {
            dbg("kickstart: SpringBoard RC not ready — init SpringBoard first before spawning \(service)")
            return false
        }

        let trojan = rc.trojanMem
        guard trojan != 0 else {
            dbg("kickstart: trojanMem is 0 for SpringBoard RC — session may be dead")
            return false
        }

        let candidates = [
            "system/\(serviceLabel)",
            "user/501/\(serviceLabel)",
        ]

        for label in candidates {
            func ws(_ off: UInt64, _ s: String) {
                let b = Array((s + "\0").utf8)
                b.withUnsafeBytes { rc.remote_write(trojan + off, from: $0.baseAddress, size: UInt64(b.count)) }
            }
            func wp(_ off: UInt64, _ v: UInt64) {
                var val = v
                rc.remote_write(trojan + off, from: &val, size: 8)
            }

            ws(0x000, "/bin/launchctl")
            ws(0x040, "launchctl")
            ws(0x060, "kickstart")
            ws(0x070, "-k")
            ws(0x080, label)
            wp(0x100, trojan + 0x040)
            wp(0x108, trojan + 0x060)
            wp(0x110, trojan + 0x070)
            wp(0x118, trojan + 0x080)
            wp(0x120, 0)

            let ret = callIn(rc: rc, name: "posix_spawn", args: [
                0, trojan + 0x000, 0, 0, trojan + 0x100, 0
            ])
            let ok = Int32(truncatingIfNeeded: ret) >= 0
            dbg("kickstart \(label) → \(ok ? "ok (ret=\(ret))" : "failed (ret=\(ret), errno=\(errno))")")
            if ok { return true }
        }

        dbg("kickstart: all domains failed for \(service)")
        return false
    }

    // MARK: - Process enumeration

    /// Lists all running processes.
    /// Primary: proclist() kernel primitive from bridging header.
    /// Fallback: sysctl KERN_PROC_ALL (standard BSD, works post-sbx-escape).
    func listRunningProcesses() -> [RunningProcess] {
        var count: Int32 = 0
        if let ptr = proclist(nil, &count), count > 0 {
            defer { free_proclist(ptr) }
            let result: [RunningProcess] = (0..<Int(count)).compactMap { i in
                let e = ptr[i]
                guard e.pid > 1 else { return nil }
                let name = withUnsafeBytes(of: e.name) { raw -> String in
                    let b   = raw.bindMemory(to: UInt8.self)
                    let end = b.firstIndex(of: 0) ?? b.endIndex
                    return String(bytes: b[..<end], encoding: .utf8) ?? ""
                }
                return name.isEmpty ? nil : RunningProcess(pid: e.pid, uid: e.uid, name: name)
            }
            if !result.isEmpty {
                return result.sorted { $0.name.lowercased() < $1.name.lowercased() }
            }
        }

        dbg("proclist returned empty — falling back to sysctl")
        return listProcessesViaSysctl()
    }

    private func listProcessesViaSysctl() -> [RunningProcess] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        let count = size / MemoryLayout<kinfo_proc>.stride
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return [] }

        return procs.compactMap { p in
            let pid = p.kp_proc.p_pid
            guard pid > 1 else { return nil }
            let name = withUnsafeBytes(of: p.kp_proc.p_comm) { raw -> String in
                let b   = raw.bindMemory(to: UInt8.self)
                let end = b.firstIndex(of: 0) ?? b.endIndex
                return String(bytes: b[..<end], encoding: .utf8) ?? ""
            }
            guard !name.isEmpty else { return nil }
            let uid = p.kp_eproc.e_ucred.cr_uid
            return RunningProcess(pid: UInt32(pid), uid: uid, name: name)
        }.sorted { $0.name.lowercased() < $1.name.lowercased() }
    }

    func isRunning(_ name: String) -> Bool {
        listRunningProcesses().contains { $0.name == name }
    }

    // MARK: - Read

    /// Read a file using the best available method.
    /// Pass `override:` to force a specific RC process (user isolation).
    /// Always call from a background queue.
    func read(path: String, maxSize: Int = 8 * 1024 * 1024,
              override: String? = nil) -> (data: Data?, result: RCIOResult) {
        let start = Date()
        dbg("READ \(path) (max=\(maxSize), override=\(override ?? "auto"))")

        // Tier 1: direct
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) {
            let trimmed = data.count > maxSize ? data.prefix(maxSize) : data
            let r = RCIOResult(ok: true, tier: .direct, process: nil, bytes: trimmed.count,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (direct, \(trimmed.count) bytes)",
                               diagnostic: "direct read succeeded")
            dbg("  → direct ok, \(trimmed.count) bytes in \(String(format: "%.0fms", r.duration * 1000))")
            appendLog(op: "read", path: path, result: r)
            return (trimmed, r)
        }
        let directErrno = errno
        dbg("  → direct failed: errno=\(directErrno) (\(String(cString: strerror(directErrno))))")

        // Tier 2: VFS
        if mgr.vfsready, let data = mgr.vfsread(path: path, maxSize: maxSize) {
            let r = RCIOResult(ok: true, tier: .vfs, process: nil, bytes: data.count,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (vfs, \(data.count) bytes)",
                               diagnostic: "direct failed (errno \(directErrno)); vfs read succeeded")
            dbg("  → vfs ok, \(data.count) bytes")
            appendLog(op: "read", path: path, result: r)
            return (data, r)
        }
        dbg("  → vfs \(mgr.vfsready ? "returned nil" : "not ready")")

        // Tier 3: RC — override → routed → all ready
        var lastDiag = "direct failed (errno \(directErrno)); vfs \(mgr.vfsready ? "returned nil" : "not ready")"
        let candidates = buildCandidates(for: path, override: override)
        dbg("  → RC candidates: \(candidates.joined(separator: " → "))")

        for process in candidates {
            guard let rc = rcProc(for: process) else {
                lastDiag += "; \(process): init failed"
                dbg("  → rc:\(process) init failed")
                continue
            }
            if let data = rcRead(rc: rc, path: path, maxSize: maxSize) {
                let r = RCIOResult(ok: true, tier: .remoteCall, process: process, bytes: data.count,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (rc:\(process), \(data.count) bytes)",
                                   diagnostic: lastDiag + "; rc:\(process) succeeded")
                dbg("  → rc:\(process) ok, \(data.count) bytes")
                appendLog(op: "read", path: path, result: r)
                return (data, r)
            }
            lastDiag += "; rc:\(process) returned nil"
            dbg("  → rc:\(process) returned nil")
        }

        let r = RCIOResult.failure("read failed (tried: \(candidates.joined(separator: ", ")))",
                                   diagnostic: lastDiag, duration: -start.timeIntervalSinceNow)
        dbg("  → READ FAILED: \(r.diagnostic)")
        appendLog(op: "read", path: path, result: r)
        return (nil, r)
    }

    // MARK: - Write

    /// Write data using the best available method.
    /// Pass `override:` to force a specific RC process (user isolation).
    /// Always call from a background queue.
    @discardableResult
    func write(path: String, data: Data, override: String? = nil) -> RCIOResult {
        let start = Date()
        let existsDirect = FileManager.default.fileExists(atPath: path)
        dbg("WRITE \(path) (\(data.count) bytes, exists=\(existsDirect), override=\(override ?? "auto"))")

        // Tier 1: direct (existing files only — can't create new with plain SBX)
        if existsDirect {
            let fd = open(path, O_WRONLY | O_TRUNC, 0o644)
            if fd != -1 {
                let n = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
                close(fd)
                if n == data.count {
                    let r = RCIOResult(ok: true, tier: .direct, process: nil, bytes: n,
                                       duration: -start.timeIntervalSinceNow,
                                       message: "ok (direct, \(n) bytes)",
                                       diagnostic: "direct write succeeded")
                    dbg("  → direct ok, \(n) bytes")
                    appendLog(op: "write", path: path, result: r)
                    return r
                }
            }
            dbg("  → direct failed: errno=\(errno)")
        }

        // Tier 2: VFS overwrite (existing inodes only)
        if mgr.vfsready && existsDirect {
            if mgr.vfsoverwritewithdata(target: path, data: data) {
                let r = RCIOResult(ok: true, tier: .vfs, process: nil, bytes: data.count,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (vfs, \(data.count) bytes)",
                                   diagnostic: "direct failed; vfs overwrite succeeded")
                dbg("  → vfs overwrite ok")
                appendLog(op: "write", path: path, result: r)
                return r
            }
            dbg("  → vfs overwrite failed")
        }

        // Tier 3: RC — can create new files, bypasses MACF
        var lastDiag = "direct \(existsDirect ? "failed errno \(errno)" : "skipped (new file)"); vfs \(mgr.vfsready ? "failed" : "not ready")"
        let candidates = buildCandidates(for: path, override: override)
        dbg("  → RC candidates: \(candidates.joined(separator: " → "))")

        for process in candidates {
            guard let rc = rcProc(for: process) else {
                lastDiag += "; \(process): init failed"
                continue
            }
            let (ok, n, diag) = rcWrite(rc: rc, path: path, data: data)
            if ok {
                let r = RCIOResult(ok: true, tier: .remoteCall, process: process, bytes: n,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (rc:\(process), \(n) bytes)",
                                   diagnostic: lastDiag + "; rc:\(process) \(diag)")
                dbg("  → rc:\(process) ok, \(n) bytes written")
                appendLog(op: "write", path: path, result: r)
                return r
            }
            lastDiag += "; rc:\(process) \(diag)"
            dbg("  → rc:\(process) failed: \(diag)")
        }

        let r = RCIOResult.failure("write failed (tried: \(candidates.joined(separator: ", ")))",
                                   diagnostic: lastDiag, duration: -start.timeIntervalSinceNow)
        dbg("  → WRITE FAILED: \(r.diagnostic)")
        appendLog(op: "write", path: path, result: r)
        return r
    }

    // MARK: - Directory listing

    /// List directory contents using the best available method.
    ///
    /// We try the given path first.  If every tier fails, we flip the /private
    /// prefix and retry — iOS symlinks mean /var and /private/var resolve to the
    /// same physical location but VFS may have indexed the entries under whichever
    /// form it first saw (usually the un-prefixed /var/... form).
    func listDir(path: String) -> (entries: [(name: String, isDir: Bool, size: Int64)], source: String) {
        dbg("LISTDIR \(path)")
        if let result = _listDirAtPath(path) {
            dbg("  → \(result.source): \(result.entries.count) entries")
            return result
        }

        // Build alternate: toggle /private prefix.
        let alt: String?
        if path.hasPrefix("/private/") {
            alt = String(path.dropFirst(8))
        } else if path != "/" && !path.hasPrefix("/private") {
            alt = "/private" + path
        } else {
            alt = nil
        }

        if let alt {
            dbg("  → primary failed, retrying with alt path: \(alt)")
            if let result = _listDirAtPath(alt) {
                dbg("  → alt \(result.source): \(result.entries.count) entries")
                return result
            }
        }

        dbg("  → LISTDIR FAILED for \(path)")
        return ([], "failed")
    }

    private func _listDirAtPath(_ path: String) -> (entries: [(name: String, isDir: Bool, size: Int64)], source: String)? {
        let fm = FileManager.default

        // Tier 1: VFS (same layer as Lara FM — try first per user spec)
        if mgr.vfsready, let items = mgr.vfslistdir(path: path) {
            let enriched = items.map { item -> (String, Bool, Int64) in
                let size = item.isDir ? Int64(-1)
                                      : mgr.vfssize(path: path + "/" + item.name)
                return (item.name, item.isDir, size)
            }
            return (enriched, "vfs")
        }

        // Tier 2: FileManager (post-sbx-escape, direct IO)
        if let names = try? fm.contentsOfDirectory(atPath: path) {
            let entries: [(String, Bool, Int64)] = names.sorted().map { name in
                let full = (path == "/" ? "" : path) + "/" + name
                var isDir: ObjCBool = false
                fm.fileExists(atPath: full, isDirectory: &isDir)
                let size = (try? fm.attributesOfItem(atPath: full)[.size] as? Int64) ?? Int64(-1)
                return (name, isDir.boolValue, size)
            }
            return (entries, "filemanager")
        }

        // Tier 3: RC opendir/readdir — privilege-escalated, reaches protected dirs
        let candidates = buildCandidates(for: path)
        for proc in candidates {
            if let items = rcListDir(path: path, process: proc) {
                let enriched: [(String, Bool, Int64)] = items.map { item in
                    let full = (path == "/" ? "" : path) + "/" + item.name
                    let size: Int64 = item.isDir ? -1
                        : ((try? fm.attributesOfItem(atPath: full)[.size] as? Int64) ?? -1)
                    return (item.name, item.isDir, size)
                }
                return (enriched, "rc:\(proc)")
            }
        }

        return nil  // All tiers failed for this path
    }

    // MARK: - RC directory listing primitive

    private func rcListDir(path: String, process: String) -> [(name: String, isDir: Bool)]? {
        poolLock.lock()
        let state = pool[process]?.state
        let rc    = pool[process]?.rc
        poolLock.unlock()
        guard case .ready = state, let rc else { return nil }

        let pathBytes = Array((path + "\0").utf8)
        let trojanMem = rc.trojanMem
        guard trojanMem != 0 else { return nil }

        pathBytes.withUnsafeBytes {
            rc.remote_write(trojanMem, from: $0.baseAddress, size: UInt64(pathBytes.count))
        }

        let dirPtr = callIn(rc: rc, name: "opendir", args: [trojanMem])
        guard dirPtr != 0 else { return nil }
        defer { _ = callIn(rc: rc, name: "closedir", args: [dirPtr]) }

        // Darwin struct dirent (sys/dirent.h):
        //   offset  0: d_ino      UInt64
        //   offset  8: d_seekoff  UInt64
        //   offset 16: d_reclen   UInt16
        //   offset 18: d_namlen   UInt16
        //   offset 20: d_type     UInt8  (DT_DIR=4, DT_REG=8, DT_LNK=10)
        //   offset 21: d_name     char[]
        let readSize: UInt64 = 21 + 256
        var result: [(name: String, isDir: Bool)] = []

        while true {
            let direntPtr = callIn(rc: rc, name: "readdir", args: [dirPtr])
            guard direntPtr != 0 else { break }

            var buf = [UInt8](repeating: 0, count: Int(readSize))
            let ok = buf.withUnsafeMutableBytes { ptr in
                rc.remoteRead(direntPtr, to: ptr.baseAddress, size: readSize)
            }
            guard ok else { continue }

            let namlen = Int(UInt16(buf[18]) | (UInt16(buf[19]) << 8))
            let dtype  = buf[20]
            guard namlen > 0, (21 + namlen) <= buf.count else { continue }

            let nameBytes = Array(buf[21..<(21 + namlen)])
            guard let name = String(bytes: nameBytes, encoding: .utf8),
                  name != ".", name != ".." else { continue }

            result.append((name: name, isDir: dtype == 4))
        }

        guard !result.isEmpty else { return nil }
        return result.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    // MARK: - Delete

    @discardableResult
    func delete(path: String, override: String? = nil) -> RCIOResult {
        let start = Date()
        dbg("DELETE \(path) (override=\(override ?? "auto"))")

        // Tier 1: direct
        if (try? FileManager.default.removeItem(atPath: path)) != nil {
            let r = RCIOResult(ok: true, tier: .direct, process: nil, bytes: 0,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (direct delete)",
                               diagnostic: "FileManager.removeItem succeeded")
            dbg("  → direct delete ok")
            appendLog(op: "delete", path: path, result: r)
            return r
        }
        dbg("  → direct delete failed: errno=\(errno)")

        // Tier 2: RC unlink/rmdir via candidates
        let candidates = buildCandidates(for: path, override: override)
        for proc in candidates {
            let (ok, diag) = rcDeleteIn(path: path, process: proc)
            if ok {
                let r = RCIOResult(ok: true, tier: .remoteCall, process: proc, bytes: 0,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (rc:\(proc) deleted)", diagnostic: diag)
                dbg("  → rc:\(proc) delete ok")
                appendLog(op: "delete", path: path, result: r)
                return r
            }
            dbg("  → rc:\(proc) delete failed: \(diag)")
        }

        let r = RCIOResult.failure("delete failed (tried: \(candidates.joined(separator: ", ")))",
                                   duration: -start.timeIntervalSinceNow)
        dbg("  → DELETE FAILED")
        appendLog(op: "delete", path: path, result: r)
        return r
    }

    private func rcDeleteIn(path: String, process: String) -> (Bool, String) {
        poolLock.lock()
        let state = pool[process]?.state
        let rc    = pool[process]?.rc
        poolLock.unlock()
        guard case .ready = state, let rc else { return (false, "\(process) not ready") }

        let pathBytes = Array((path + "\0").utf8)
        let trojan    = rc.trojanMem
        guard trojan != 0 else { return (false, "trojanMem is 0") }
        pathBytes.withUnsafeBytes { rc.remote_write(trojan, from: $0.baseAddress, size: UInt64(pathBytes.count)) }

        let ul = Int32(bitPattern: UInt32(callIn(rc: rc, name: "unlink", args: [trojan]) & 0xFFFFFFFF))
        if ul == 0 { return (true, "\(process) unlink ok") }
        let rd = Int32(bitPattern: UInt32(callIn(rc: rc, name: "rmdir",  args: [trojan]) & 0xFFFFFFFF))
        if rd == 0 { return (true, "\(process) rmdir ok") }
        return (false, "unlink errno=\(ul) rmdir errno=\(rd)")
    }

    // MARK: - Move / Rename

    @discardableResult
    func move(from srcPath: String, to dstPath: String, override: String? = nil) -> RCIOResult {
        let start = Date()
        dbg("MOVE \(srcPath) → \(dstPath) (override=\(override ?? "auto"))")

        // Tier 1: direct
        if (try? FileManager.default.moveItem(atPath: srcPath, toPath: dstPath)) != nil {
            let r = RCIOResult(ok: true, tier: .direct, process: nil, bytes: 0,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (direct move)",
                               diagnostic: "FileManager.moveItem succeeded")
            dbg("  → direct move ok")
            appendLog(op: "move", path: srcPath, result: r)
            return r
        }
        dbg("  → direct move failed: errno=\(errno)")

        // Tier 2: RC rename(2) via candidates
        let candidates = buildCandidates(for: srcPath, override: override)
        for proc in candidates {
            poolLock.lock()
            let state = pool[proc]?.state
            let rc    = pool[proc]?.rc
            poolLock.unlock()
            guard case .ready = state, let rc else { continue }

            let trojan = rc.trojanMem
            guard trojan != 0 else { continue }

            let srcBytes = Array((srcPath + "\0").utf8)
            let dstBytes = Array((dstPath + "\0").utf8)
            let srcLen   = UInt64(srcBytes.count)

            srcBytes.withUnsafeBytes { rc.remote_write(trojan, from: $0.baseAddress, size: srcLen) }
            let dstAddr = trojan + srcLen
            dstBytes.withUnsafeBytes { rc.remote_write(dstAddr, from: $0.baseAddress, size: UInt64(dstBytes.count)) }

            let ret = Int32(bitPattern: UInt32(callIn(rc: rc, name: "rename", args: [trojan, dstAddr]) & 0xFFFFFFFF))
            if ret == 0 {
                let r = RCIOResult(ok: true, tier: .remoteCall, process: proc, bytes: 0,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (rc:\(proc) renamed)",
                                   diagnostic: "\(proc) rename ok")
                dbg("  → rc:\(proc) rename ok")
                appendLog(op: "move", path: srcPath, result: r)
                return r
            }
            dbg("  → rc:\(proc) rename failed: ret=\(ret)")
        }

        let r = RCIOResult.failure("move failed", duration: -start.timeIntervalSinceNow)
        dbg("  → MOVE FAILED")
        appendLog(op: "move", path: srcPath, result: r)
        return r
    }

    // MARK: - Mkdir (new)

    /// Create a directory using the best available method.
    @discardableResult
    func mkdir(path: String, override: String? = nil) -> RCIOResult {
        let start = Date()
        dbg("MKDIR \(path) (override=\(override ?? "auto"))")

        // Tier 1: direct FileManager
        if (try? FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)) != nil {
            let r = RCIOResult(ok: true, tier: .direct, process: nil, bytes: 0,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (direct mkdir)",
                               diagnostic: "FileManager.createDirectory succeeded")
            dbg("  → direct mkdir ok")
            appendLog(op: "mkdir", path: path, result: r)
            return r
        }
        dbg("  → direct mkdir failed: errno=\(errno)")

        // Tier 2: RC mkdir(2) — mode 0755
        let candidates = buildCandidates(for: path, override: override)
        for proc in candidates {
            poolLock.lock()
            let state = pool[proc]?.state
            let rc    = pool[proc]?.rc
            poolLock.unlock()
            guard case .ready = state, let rc else { continue }

            let trojan = rc.trojanMem
            guard trojan != 0 else { continue }

            let pathBytes = Array((path + "\0").utf8)
            pathBytes.withUnsafeBytes { rc.remote_write(trojan, from: $0.baseAddress, size: UInt64(pathBytes.count)) }

            let ret = Int32(bitPattern: UInt32(callIn(rc: rc, name: "mkdir", args: [trojan, 0o755]) & 0xFFFFFFFF))
            if ret == 0 {
                let r = RCIOResult(ok: true, tier: .remoteCall, process: proc, bytes: 0,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (rc:\(proc) mkdir)",
                                   diagnostic: "\(proc) mkdir ok")
                dbg("  → rc:\(proc) mkdir ok")
                appendLog(op: "mkdir", path: path, result: r)
                return r
            }
            dbg("  → rc:\(proc) mkdir failed: ret=\(ret)")
        }

        let r = RCIOResult.failure("mkdir failed", duration: -start.timeIntervalSinceNow)
        dbg("  → MKDIR FAILED")
        appendLog(op: "mkdir", path: path, result: r)
        return r
    }

    // MARK: - RC read/write primitives

    private func rcRead(rc: RemoteCall, path: String, maxSize: Int) -> Data? {
        let pathBytes = Array((path + "\0").utf8)
        let trojanMem = rc.trojanMem
        guard trojanMem != 0 else { return nil }

        pathBytes.withUnsafeBytes {
            rc.remote_write(trojanMem, from: $0.baseAddress, size: UInt64(pathBytes.count))
        }

        let fd = callIn(rc: rc, name: "open", args: [trojanMem, 0, 0])
        guard Int32(bitPattern: UInt32(fd & 0xFFFFFFFF)) >= 0 else { return nil }
        defer { _ = callIn(rc: rc, name: "close", args: [fd]) }

        let remoteBuf = callIn(rc: rc, name: "mmap", args: [
            0, UInt64(maxSize), 3, 0x1002, UInt64(bitPattern: Int64(-1)), 0
        ])
        guard remoteBuf != 0, remoteBuf != UInt64(bitPattern: -1) else { return nil }
        defer { _ = callIn(rc: rc, name: "munmap", args: [remoteBuf, UInt64(maxSize)]) }

        let n = callIn(rc: rc, name: "read", args: [fd, remoteBuf, UInt64(maxSize)])
        guard n > 0 else { return nil }

        var local = [UInt8](repeating: 0, count: Int(n))
        let ok = local.withUnsafeMutableBytes {
            rc.remoteRead(remoteBuf, to: $0.baseAddress, size: n)
        }
        return ok ? Data(local) : nil
    }

    private func rcWrite(rc: RemoteCall, path: String, data: Data) -> (Bool, Int, String) {
        let pathBytes = Array((path + "\0").utf8)
        let trojanMem = rc.trojanMem
        guard trojanMem != 0 else { return (false, 0, "trojanMem is 0") }

        pathBytes.withUnsafeBytes {
            rc.remote_write(trojanMem, from: $0.baseAddress, size: UInt64(pathBytes.count))
        }

        let remoteBuf = callIn(rc: rc, name: "mmap", args: [
            0, UInt64(data.count), 3, 0x1002, UInt64(bitPattern: Int64(-1)), 0
        ])
        guard remoteBuf != 0, remoteBuf != UInt64(bitPattern: -1) else {
            return (false, 0, "mmap failed")
        }
        defer { _ = callIn(rc: rc, name: "munmap", args: [remoteBuf, UInt64(data.count)]) }

        data.withUnsafeBytes {
            rc.remote_write(remoteBuf, from: $0.baseAddress, size: UInt64(data.count))
        }

        let fd = callIn(rc: rc, name: "open", args: [trojanMem, 0x601, 0o644]) // O_WRONLY|O_CREAT|O_TRUNC
        guard Int32(bitPattern: UInt32(fd & 0xFFFFFFFF)) >= 0 else {
            return (false, 0, "open() returned \(fd)")
        }

        let written = callIn(rc: rc, name: "write", args: [fd, remoteBuf, UInt64(data.count)])
        _ = callIn(rc: rc, name: "close", args: [fd])

        let n = Int(written)
        return n == data.count
            ? (true, n, "open+write+close ok")
            : (false, n, "write short \(n)/\(data.count)")
    }

    // MARK: - Process routing

    /// Maps a path to the process most likely to have the required MAC context.
    func rcBestProcess(for path: String) -> String {
        // Normalise /private prefix — /private/var == /var on iOS
        let p = path.hasPrefix("/private") ? String(path.dropFirst(8)) : path

        switch true {
        case p.hasPrefix("/var/mobile"),
             p.hasPrefix("/var/containers"):
            return Self.backupDaemonName

        case p.hasPrefix("/var/db/MobileIdentityData"):
            return "mobileidentityd"

        case p.hasPrefix("/var/Keychains"):
            return "securityd"

        case p.hasPrefix("/var/db/DPLA"),
             p.hasPrefix("/var/mobile/Library/DataAccess"):
            return "dataaccessd"

        case p.hasPrefix("/var/mobile/Library/Media"),
             p.hasPrefix("/var/mobile/Media"):
            return "mediaserverd"

        case p.hasPrefix("/var/root"),
             p.hasPrefix("/var/db"):
            return "configd"

        default:
            return "SpringBoard"
        }
    }

    /// Builds the ordered RC candidate list for a given path:
    ///   override (if set) → routed process → all other currently-ready pool processes.
    func buildCandidates(for path: String, override: String? = nil) -> [String] {
        var order: [String] = []
        if let ov = override { order.append(ov) }
        let routed = rcBestProcess(for: path)
        if !order.contains(routed) { order.append(routed) }

        poolLock.lock()
        let ready = pool.values
            .filter { $0.state.isReady && !order.contains($0.process) }
            .sorted { $0.process < $1.process }
            .map { $0.process }
        poolLock.unlock()
        return order + ready
    }

    // MARK: - Generic RC call helper

    @discardableResult
    func callIn(rc: RemoteCall, name: String, args: [UInt64], timeout: Int32 = 300) -> UInt64 {
        let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
        guard let ptr = dlsym(RTLD_DEFAULT, name) else { return 0 }
        var a = args
        return name.withCString { cname in
            UInt64(a.withUnsafeMutableBufferPointer { buf in
                rc.doStable(
                    withTimeout: timeout,
                    functionName: UnsafeMutablePointer(mutating: cname),
                    functionPointer: ptr,
                    args: buf.baseAddress,
                    argCount: UInt(args.count)
                ) ?? 0
            })
        }
    }

    // MARK: - Private helpers

    private func markPoolState(_ process: String, _ state: RCPoolEntry.State) {
        poolLock.lock()
        pool[process] = RCPoolEntry(process: process, state: state, rc: pool[process]?.rc)
        poolLock.unlock()
        publish()
    }

    private func markFailed(process: String, reason: String) {
        markPoolState(process, .failed(reason: reason))
        dbg("\(process) failed: \(reason)")
    }

    private func publish() {
        DispatchQueue.main.async { self.objectWillChange.send() }
    }

    private func appendLog(op: String, path: String, result: RCIOResult) {
        let entry = RCIOLogEntry(timestamp: Date(), operation: op, path: path, result: result)
        DispatchQueue.main.async {
            self.log.insert(entry, at: 0)
            if self.log.count > 200 { self.log = Array(self.log.prefix(200)) }
        }
    }

    /// Clear all log entries.
    func clearLog() {
        DispatchQueue.main.async {
            self.log.removeAll()
        }
        dbg("log cleared")
    }
}

// MARK: - Formatters

extension Int64 {
    var fileSizeString: String {
        guard self >= 0 else { return "—" }
        if self < 1024          { return "\(self) B" }
        if self < 1024 * 1024   { return String(format: "%.1f KB", Double(self) / 1024) }
        return String(format: "%.1f MB", Double(self) / (1024 * 1024))
    }
}

extension RCIOResult {
    var tierColor: String {
        switch tier {
        case .direct:     return "green"
        case .vfs:        return "blue"
        case .remoteCall: return "orange"
        case .failed:     return "red"
        }
    }
}
