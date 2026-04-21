//
//  RemoteFileIO.swift
//  lara
//
//  RemoteCall-backed file I/O engine.
//
//  Process pool and routing:
//    mobile_backup_agent2  mobile + broad backup entitlement  (widest /var/mobile reach)
//    SpringBoard           mobile uid                          (default /var/mobile/**)
//    configd               root uid                            (/var/db/*, /var/root/*)
//    mobileidentityd       MobileIdentityData MAC label        (spawned on demand)
//    securityd             Keychains MAC label
//    dataaccessd           DPLA / DataAccess                   (spawned on demand)
//    mediaserverd          Media library paths
//
//  Fallback chain per operation:
//    1. Direct I/O (post-sbx-escape)
//    2. VFS overwrite (existing inodes only)
//    3. override process (if set)
//    4. routed process
//    5. all other currently-ready pool processes
//    6. fail with full diagnostic

import Foundation
import Combine
import Darwin

// MARK: - Diagnostics

enum RCIOTier: String, CustomStringConvertible {
    case direct     = "direct"
    case vfs        = "vfs"
    case remoteCall = "remotecall"
    case failed     = "failed"
    var description: String { rawValue }
}

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

struct RCIOLogEntry: Identifiable {
    let id        = UUID()
    let timestamp: Date
    let operation:  String
    let path:       String
    let result:     RCIOResult

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
        case spawning           // launchctl kickstart in progress
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

// MARK: - Running process info (from proclist C API)

struct RunningProcess: Identifiable {
    let id   = UUID()
    let pid:  UInt32
    let uid:  UInt32
    let name: String
    var isRoot: Bool { uid == 0 }
}

// MARK: - RemoteFileIO

final class RemoteFileIO: ObservableObject {

    static let shared = RemoteFileIO()

    @Published private(set) var pool: [String: RCPoolEntry] = [:]
    @Published private(set) var log:  [RCIOLogEntry] = []

    private let mgr      = laramgr.shared
    private let poolLock = NSLock()

    // Curated list shown in ProcessSelectorView
    static let recommendedProcesses: [String] = [
        "mobile_backup_agent2",
        "SpringBoard",
        "configd",
        "mobileidentityd",
        "securityd",
        "dataaccessd",
        "mediaserverd",
    ]

    // Processes that likely need spawning before RC init
    private static let spawnNeeded: Set<String> = ["mobileidentityd", "dataaccessd"]

    // launchd service names for kickstart
    private static let launchdServices: [String: String] = [
        "mobileidentityd": "com.apple.mobileidentityd",
        "dataaccessd":     "com.apple.dataaccessd",
    ]

    private init() {
        for p in Self.recommendedProcesses {
            pool[p] = RCPoolEntry(process: p, state: .uninitialized, rc: nil)
        }
    }

    // MARK: - Pool management

    /// Returns a ready RC for `process`.
    /// If the process is in `spawnNeeded` and not running, kicks it via launchctl first.
    /// Always call from a background queue.
    func rcProc(for process: String, spawnIfNeeded: Bool = true) -> RemoteCall? {
        poolLock.lock()
        let entry = pool[process]
        poolLock.unlock()

        if let rc = entry?.rc, entry?.state.isReady == true { return rc }
        if case .failed = entry?.state { return nil }

        guard mgr.dsready else {
            markFailed(process: process, reason: "darksword not ready")
            return nil
        }

        // Spawn the daemon if needed and not already running
        if spawnIfNeeded, Self.spawnNeeded.contains(process), !isRunning(process) {
            markPoolState(process, .spawning)
            guard kickstart(service: process) else {
                markFailed(process: process, reason: "kickstart failed")
                return nil
            }
            // Wait up to 3 s for the daemon to appear in proclist
            var appeared = false
            for _ in 1...6 {
                Thread.sleep(forTimeInterval: 0.5)
                if isRunning(process) { appeared = true; break }
            }
            guard appeared else {
                markFailed(process: process, reason: "daemon did not appear after kickstart")
                return nil
            }
        }

        markPoolState(process, .initializing)

        guard let rc = RemoteCall(process: process, useMigFilterBypass: false) else {
            markFailed(process: process, reason: "RemoteCall init returned nil")
            return nil
        }

        let pid = Int32(truncatingIfNeeded: callIn(rc: rc, name: "getpid", args: []))

        poolLock.lock()
        pool[process] = RCPoolEntry(process: process, state: .ready(pid: pid), rc: rc)
        poolLock.unlock()
        publish()
        mgr.logmsg("(rcio) ready: \(process) pid=\(pid)")
        return rc
    }

    func destroyProc(_ process: String) {
        poolLock.lock()
        let old = pool[process]
        pool[process] = RCPoolEntry(process: process, state: .uninitialized, rc: nil)
        poolLock.unlock()
        old?.rc?.destroy()
        publish()
    }

    func resetProc(_ process: String) {
        poolLock.lock()
        if case .failed = pool[process]?.state {
            pool[process] = RCPoolEntry(process: process, state: .uninitialized, rc: nil)
        }
        poolLock.unlock()
        publish()
    }

    /// Add an arbitrary (non-recommended) process to the pool for debug use.
    func addArbitraryProcess(_ name: String) {
        poolLock.lock()
        if pool[name] == nil {
            pool[name] = RCPoolEntry(process: name, state: .uninitialized, rc: nil)
        }
        poolLock.unlock()
        publish()
    }

    // MARK: - Spawn / kickstart

    /// Spawn a registered launchd service by running
    /// `launchctl kickstart -k system/<service>` inside SpringBoard's RC session.
    @discardableResult
    func kickstart(service: String) -> Bool {
        let label = "system/\(Self.launchdServices[service] ?? service)"

        poolLock.lock()
        let sbEntry = pool["SpringBoard"]
        poolLock.unlock()
        guard case .ready = sbEntry?.state, let rc = sbEntry?.rc else {
            mgr.logmsg("(rcio) kickstart: SpringBoard RC not ready, cannot spawn \(service)")
            return false
        }

        let trojan = rc.trojanMem
        guard trojan != 0 else { return false }

        // Write strings + argv pointer array into trojanMem
        // Layout:
        //   0x000: path "/bin/launchctl\0"
        //   0x040: "launchctl\0"  (argv[0])
        //   0x060: "kickstart\0"  (argv[1])
        //   0x070: "-k\0"         (argv[2])
        //   0x080: label\0        (argv[3])
        //   0x100: argv[0] ptr
        //   0x108: argv[1] ptr
        //   0x110: argv[2] ptr
        //   0x118: argv[3] ptr
        //   0x120: NULL

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
        mgr.logmsg("(rcio) kickstart \(label) -> \(ok ? "ok" : "failed ret=\(ret)")")
        return ok
    }

    // MARK: - Process enumeration

    /// Lists all running processes using the proclist() kernel primitive from utils.h.
    func listRunningProcesses() -> [RunningProcess] {
        var count: Int32 = 0
        guard let ptr = proclist(nil, &count), count > 0 else { return [] }
        defer { free_proclist(ptr) }
        return (0..<Int(count)).compactMap { (i: Int) -> RunningProcess? in // Added explicit return type
            let e = ptr[i]
            guard e.pid > 1 else { return nil } // Now compatible!
            let name = withUnsafeBytes(of: e.name) { raw -> String in
                let b = raw.bindMemory(to: UInt8.self)
                let end = b.firstIndex(of: 0) ?? b.endIndex
                return String(bytes: b[..<end], encoding: .utf8) ?? ""
            }
            return name.isEmpty ? nil : RunningProcess(pid: e.pid, uid: e.uid, name: name)
        }.sorted { $0.name.lowercased() < $1.name.lowercased() }
    }

    func isRunning(_ name: String) -> Bool {
        listRunningProcesses().contains { $0.name == name }
    }

    // MARK: - Read

    /// Read a file using the best available method.
    /// - parameter override: If set, this process is tried first in the RC tier.
    /// Always call from a background queue.
    func read(path: String, maxSize: Int = 8 * 1024 * 1024,
              override: String? = nil) -> (data: Data?, result: RCIOResult) {
        let start = Date()

        // Tier 1: direct
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) {
            let trimmed = data.count > maxSize ? data.prefix(maxSize) : data
            let r = RCIOResult(ok: true, tier: .direct, process: nil, bytes: trimmed.count,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (direct, \(trimmed.count) bytes)",
                               diagnostic: "direct read succeeded")
            appendLog(op: "read", path: path, result: r)
            return (trimmed, r)
        }

        // Tier 2: VFS
        if mgr.vfsready, let data = mgr.vfsread(path: path, maxSize: maxSize) {
            let r = RCIOResult(ok: true, tier: .vfs, process: nil, bytes: data.count,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (vfs, \(data.count) bytes)",
                               diagnostic: "direct failed (errno \(errno)); vfs read succeeded")
            appendLog(op: "read", path: path, result: r)
            return (data, r)
        }

        // Tier 3: RemoteCall — override → routed → all ready
        var lastDiag = "direct failed (errno \(errno)); vfs \(mgr.vfsready ? "returned nil" : "not ready")"
        let candidates = buildCandidates(for: path, override: override)

        for process in candidates {
            guard let rc = rcProc(for: process) else {
                lastDiag += "; \(process): init failed"
                continue
            }
            if let data = rcRead(rc: rc, path: path, maxSize: maxSize) {
                let r = RCIOResult(ok: true, tier: .remoteCall, process: process, bytes: data.count,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (rc:\(process), \(data.count) bytes)",
                                   diagnostic: lastDiag + "; rc:\(process) succeeded")
                appendLog(op: "read", path: path, result: r)
                return (data, r)
            }
            lastDiag += "; rc:\(process) returned nil"
        }

        let r = RCIOResult.failure("read failed (tried: \(candidates.joined(separator: ", ")))",
                                   diagnostic: lastDiag, duration: -start.timeIntervalSinceNow)
        appendLog(op: "read", path: path, result: r)
        return (nil, r)
    }

    // MARK: - Write

    /// Write data using the best available method.
    /// - parameter override: If set, this process is tried first in the RC tier.
    /// Always call from a background queue.
    @discardableResult
    func write(path: String, data: Data, override: String? = nil) -> RCIOResult {
        let start = Date()
        let existsDirect = FileManager.default.fileExists(atPath: path)

        // Tier 1: direct (existing files only)
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
                    appendLog(op: "write", path: path, result: r)
                    return r
                }
            }
        }

        // Tier 2: VFS overwrite (existing inodes only)
        if mgr.vfsready && existsDirect {
            if mgr.vfsoverwritewithdata(target: path, data: data) {
                let r = RCIOResult(ok: true, tier: .vfs, process: nil, bytes: data.count,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (vfs, \(data.count) bytes)",
                                   diagnostic: "direct failed; vfs overwrite succeeded")
                appendLog(op: "write", path: path, result: r)
                return r
            }
        }

        // Tier 3: RemoteCall — can create new files, bypasses MACF
        var lastDiag = "direct \(existsDirect ? "failed errno \(errno)" : "skipped (new file)"); vfs \(mgr.vfsready ? "failed" : "not ready")"
        let candidates = buildCandidates(for: path, override: override)

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
                appendLog(op: "write", path: path, result: r)
                return r
            }
            lastDiag += "; rc:\(process) \(diag)"
        }

        let r = RCIOResult.failure("write failed (tried: \(candidates.joined(separator: ", ")))",
                                   diagnostic: lastDiag, duration: -start.timeIntervalSinceNow)
        appendLog(op: "write", path: path, result: r)
        return r
    }

    // MARK: - RC primitives

    private func rcRead(rc: RemoteCall, path: String, maxSize: Int) -> Data? {
        let pathBytes = Array((path + "\0").utf8)
        let trojanMem = rc.trojanMem; guard trojanMem != 0 else { return nil }

        pathBytes.withUnsafeBytes { rc.remote_write(trojanMem, from: $0.baseAddress, size: UInt64(pathBytes.count)) }

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
        let ok = local.withUnsafeMutableBytes { rc.remoteRead(remoteBuf, to: $0.baseAddress, size: n) }
        return ok ? Data(local) : nil
    }

    private func rcWrite(rc: RemoteCall, path: String, data: Data) -> (Bool, Int, String) {
        let pathBytes = Array((path + "\0").utf8)
        let trojanMem = rc.trojanMem; guard trojanMem != 0 else { return (false, 0, "trojanMem is 0") }

        pathBytes.withUnsafeBytes { rc.remote_write(trojanMem, from: $0.baseAddress, size: UInt64(pathBytes.count)) }

        let remoteBuf = callIn(rc: rc, name: "mmap", args: [
            0, UInt64(data.count), 3, 0x1002, UInt64(bitPattern: Int64(-1)), 0
        ])
        guard remoteBuf != 0, remoteBuf != UInt64(bitPattern: -1) else { return (false, 0, "mmap failed") }
        defer { _ = callIn(rc: rc, name: "munmap", args: [remoteBuf, UInt64(data.count)]) }

        data.withUnsafeBytes { rc.remote_write(remoteBuf, from: $0.baseAddress, size: UInt64(data.count)) }

        // O_WRONLY|O_CREAT|O_TRUNC = 0x601
        let fd = callIn(rc: rc, name: "open", args: [trojanMem, 0x601, 0o644])
        guard Int32(bitPattern: UInt32(fd & 0xFFFFFFFF)) >= 0 else { return (false, 0, "open() returned \(fd)") }

        let written = callIn(rc: rc, name: "write", args: [fd, remoteBuf, UInt64(data.count)])
        _ = callIn(rc: rc, name: "close", args: [fd])

        let n = Int(written)
        return n == data.count ? (true, n, "open+write+close ok") : (false, n, "write short \(n)/\(data.count)")
    }

    // MARK: - Process routing

    /// Maps a path to the process most likely to have the required MAC context.
    func rcBestProcess(for path: String) -> String {
        // Normalise /private prefix for comparison
        let p = path.hasPrefix("/private") ? String(path.dropFirst(8)) : path
        switch true {
        // MobileBackup2 gets priority for broad /var/mobile writes — its backup
        // entitlement gives it wider write surface than a plain mobile-uid process.
        case p.hasPrefix("/var/mobile"),
             p.hasPrefix("/var/containers"):
            return "mobile_backup_agent2"

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

    /// Builds the ordered candidate list for RC operations:
    ///   override (if set) → routed process → all other ready pool processes.
    /// This means if the primary process fails, every already-initialised session
    /// is tried automatically before giving up.
    func buildCandidates(for path: String, override: String? = nil) -> [String] {
        var order: [String] = []
        if let ov = override { order.append(ov) }
        let routed = rcBestProcess(for: path)
        if !order.contains(routed) { order.append(routed) }

        // Append every other currently-ready process as additional fallback
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

    // MARK: - Directory listing

    func listDir(path: String) -> (entries: [(name: String, isDir: Bool, size: Int64)], source: String) {
        if mgr.vfsready, let items = mgr.vfslistdir(path: path) {
            let enriched = items.map { (name: $0.name, isDir: $0.isDir,
                                        size: $0.isDir ? -1 : mgr.vfssize(path: path + "/" + $0.name)) }
            return (enriched, "vfs")
        }
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: path) else { return ([], "failed") }
        let entries = names.sorted().map { name -> (String, Bool, Int64) in
            let full = path + "/" + name
            var isDir: ObjCBool = false
            fm.fileExists(atPath: full, isDirectory: &isDir)
            let size = (try? fm.attributesOfItem(atPath: full)[.size] as? Int64) ?? -1
            return (name, isDir.boolValue, size ?? -1)
        }
        return (entries, "filemanager")
    }

    // MARK: - Delete / Move (unchanged from original)

    func delete(path: String) -> RCIOResult {
        let start = Date()
        if (try? FileManager.default.removeItem(atPath: path)) != nil {
            let r = RCIOResult(ok: true, tier: .direct, process: nil, bytes: 0,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (direct delete)", diagnostic: "FileManager.removeItem succeeded")
            appendLog(op: "delete", path: path, result: r); return r
        }
        let candidates = buildCandidates(for: path)
        for proc in candidates {
            let (ok, diag) = rcDeleteIn(path: path, process: proc)
            if ok {
                let r = RCIOResult(ok: true, tier: .remoteCall, process: proc, bytes: 0,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (rc:\(proc) deleted)", diagnostic: diag)
                appendLog(op: "delete", path: path, result: r); return r
            }
        }
        let r = RCIOResult.failure("delete failed", duration: -start.timeIntervalSinceNow)
        appendLog(op: "delete", path: path, result: r); return r
    }

    private func rcDeleteIn(path: String, process: String) -> (Bool, String) {
        poolLock.lock()
        let state = pool[process]?.state
        let rc    = pool[process]?.rc
        poolLock.unlock()
        guard case .ready = state, let rc else { return (false, "\(process) not ready") }
        let pathBytes = Array((path + "\0").utf8)
        let trojan    = rc.trojanMem; guard trojan != 0 else { return (false, "trojanMem is 0") }
        pathBytes.withUnsafeBytes { rc.remote_write(trojan, from: $0.baseAddress, size: UInt64(pathBytes.count)) }
        let ul = Int32(bitPattern: UInt32(callIn(rc: rc, name: "unlink", args: [trojan]) & 0xFFFFFFFF))
        if ul == 0 { return (true, "\(process) unlink ok") }
        let rd = Int32(bitPattern: UInt32(callIn(rc: rc, name: "rmdir",  args: [trojan]) & 0xFFFFFFFF))
        if rd == 0 { return (true, "\(process) rmdir ok") }
        return (false, "unlink errno=\(ul) rmdir errno=\(rd)")
    }

    func move(from srcPath: String, to dstPath: String) -> RCIOResult {
        let start = Date()
        if (try? FileManager.default.moveItem(atPath: srcPath, toPath: dstPath)) != nil {
            let r = RCIOResult(ok: true, tier: .direct, process: nil, bytes: 0,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (direct move)", diagnostic: "FileManager.moveItem succeeded")
            appendLog(op: "move", path: srcPath, result: r); return r
        }
        for proc in buildCandidates(for: srcPath) {
            poolLock.lock()
            let state = pool[proc]?.state
            let rc    = pool[proc]?.rc
            poolLock.unlock()
            guard case .ready = state, let rc else { continue }
            let trojan = rc.trojanMem; guard trojan != 0 else { continue }
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
                                   message: "ok (rc:\(proc) renamed)", diagnostic: "\(proc) rename ok")
                appendLog(op: "move", path: srcPath, result: r); return r
            }
        }
        let r = RCIOResult.failure("move failed", duration: -start.timeIntervalSinceNow)
        appendLog(op: "move", path: srcPath, result: r); return r
    }

    // MARK: - Private helpers

    private func markPoolState(_ process: String, _ state: RCPoolEntry.State) {
        poolLock.lock()
        pool[process] = RCPoolEntry(process: process, state: state, rc: pool[process]?.rc)
        poolLock.unlock()
        publish()
    }

    private func markInitializing(process: String) {
        markPoolState(process, .initializing)
    }

    private func markFailed(process: String, reason: String) {
        markPoolState(process, .failed(reason: reason))
        mgr.logmsg("(rcio) \(process) failed: \(reason)")
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
