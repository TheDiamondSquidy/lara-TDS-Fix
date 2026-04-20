//
//  RemoteFileIO.swift
//  lara
//
//  RemoteCall-backed file I/O engine.
//
//  Architecture:
//    Each process in the pool gives lara a different MAC security context.
//    Reads and writes execute open/read/write/close inside the target process
//    via thread hijacking, inheriting its credentials and entitlements.
//
//  Fallback chain (per operation):
//    1. Direct I/O       — fastest, works post-sbx-escape for most /var paths
//    2. VFS overwrite    — existing inodes only, no new file creation
//    3. RemoteCall       — routed process (creates new files, bypasses MACF)
//    4. RemoteCall root  — configd fallback (root uid, broader reach)
//    5. Fail             — full diagnostic string returned
//
//  Process routing:
//    SpringBoard      mobile uid   /var/mobile/**, /var/containers/**  (default)
//    configd          root uid     /private/var/db/**, /private/var/root/**
//    mobileidentityd  MAC label    /private/var/db/MobileIdentityData/**
//    securityd        MAC label    /private/var/Keychains/**
//    dataaccessd      MAC label    /private/var/db/DPLA/**, DataAccess/**
//    mediaserverd     mobile       /var/mobile/Library/Media/**
//

import Foundation
import Combine
import Darwin

// MARK: - Diagnostics types

/// Tier that ultimately succeeded (or the last attempted before failure)
enum RCIOTier: String, CustomStringConvertible {
    case direct       = "direct"
    case vfs          = "vfs"
    case remoteCall   = "remotecall"
    case failed       = "failed"

    var description: String { rawValue }
}

/// Full result of a single read or write operation
struct RCIOResult {
    let ok: Bool
    let tier: RCIOTier
    let process: String?         // RC process used, if any
    let bytes: Int               // bytes transferred
    let duration: TimeInterval   // wall-clock seconds
    let message: String          // human-readable summary
    let diagnostic: String       // verbose detail for debug panel

    static func failure(_ msg: String, diagnostic: String = "", duration: TimeInterval = 0) -> RCIOResult {
        RCIOResult(ok: false, tier: .failed, process: nil, bytes: 0, duration: duration, message: msg, diagnostic: diagnostic)
    }
}

/// Single entry in the operation log
struct RCIOLogEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let operation: String       // "read" / "write"
    let path: String
    let result: RCIOResult

    var summary: String {
        let ts = DateFormatter.localizedString(from: timestamp, dateStyle: .none, timeStyle: .medium)
        let status = result.ok ? "✓" : "✗"
        return "[\(ts)] \(status) \(operation) \(URL(fileURLWithPath: path).lastPathComponent) — \(result.message)"
    }
}

/// Per-process RC pool entry — tracks init status and PID for display
struct RCPoolEntry {
    enum State: CustomStringConvertible {
        case uninitialized
        case initializing
        case ready(pid: Int32)
        case failed(reason: String)

        var description: String {
            switch self {
            case .uninitialized:         return "uninitialized"
            case .initializing:          return "initializing..."
            case .ready(let pid):        return "ready (pid \(pid))"
            case .failed(let reason):    return "failed: \(reason)"
            }
        }

        var isReady: Bool {
            if case .ready = self { return true }
            return false
        }
    }

    let process: String
    var state: State
    var rc: RemoteCall?
}

// MARK: - RemoteFileIO

final class RemoteFileIO: ObservableObject {

    static let shared = RemoteFileIO()

    // Published so FileManagerView can observe pool state live
    @Published private(set) var pool: [String: RCPoolEntry] = [:]
    @Published private(set) var log: [RCIOLogEntry] = []

    private let mgr = laramgr.shared
    private let poolLock = NSLock()

    // Ordered list of processes to try as fallback if the routed one fails
    private static let fallbackOrder: [String] = [
        "configd",        // root uid — broadest fallback
        "SpringBoard",    // mobile uid — already initialized
    ]

    private init() {
        // Pre-populate pool entries so the debug panel shows all slots
        for process in ["SpringBoard", "configd", "mobileidentityd",
                        "securityd", "dataaccessd", "mediaserverd"] {
            pool[process] = RCPoolEntry(process: process, state: .uninitialized, rc: nil)
        }
    }

    // MARK: - Pool management

    /// Returns a ready RC instance for `process`, initialising it if needed.
    /// Always call from a background queue — init can take several seconds.
    func rcProc(for process: String) -> RemoteCall? {
        poolLock.lock()
        let entry = pool[process]
        poolLock.unlock()

        // Already ready
        if let rc = entry?.rc, entry?.state.isReady == true { return rc }

        // Already failed — don't retry until explicitly reset
        if case .failed = entry?.state { return nil }

        // Initialise
        guard mgr.dsready else {
            markFailed(process: process, reason: "darksword not ready")
            return nil
        }

        markInitializing(process: process)

        let rc = RemoteCall(process: process, useMigFilterBypass: false)
        guard let rc else {
            markFailed(process: process, reason: "RemoteCall init returned nil")
            return nil
        }

        // Probe pid to confirm the session is alive
        let pid = Int32(truncatingIfNeeded: callIn(rc: rc, name: "getpid", args: []))

        poolLock.lock()
        pool[process] = RCPoolEntry(process: process, state: .ready(pid: pid), rc: rc)
        poolLock.unlock()

        DispatchQueue.main.async { self.objectWillChange.send() }
        mgr.logmsg("(rcio) initialized \(process) pid=\(pid)")
        return rc
    }

    /// Tears down a single pool entry and frees the remote thread.
    func destroyProc(_ process: String) {
        poolLock.lock()
        let entry = pool[process]
        pool[process] = RCPoolEntry(process: process, state: .uninitialized, rc: nil)
        poolLock.unlock()
        entry?.rc?.destroy()
        DispatchQueue.main.async { self.objectWillChange.send() }
    }

    /// Resets a failed entry so it can be retried.
    func resetProc(_ process: String) {
        poolLock.lock()
        if case .failed = pool[process]?.state {
            pool[process] = RCPoolEntry(process: process, state: .uninitialized, rc: nil)
        }
        poolLock.unlock()
        DispatchQueue.main.async { self.objectWillChange.send() }
    }

    // MARK: - Public I/O API

    /// Read a file using the best available method.
    /// Always call from a background queue.
    func read(path: String, maxSize: Int = 8 * 1024 * 1024) -> (data: Data?, result: RCIOResult) {
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

        // Tier 3: RemoteCall — try routed process then fallbacks
        let targeted = rcBestProcess(for: path)
        var tried: [String] = []
        var lastDiag = "direct failed (errno \(errno)); vfs \(mgr.vfsready ? "returned nil" : "not ready")"

        for process in ([targeted] + Self.fallbackOrder.filter { $0 != targeted }) {
            tried.append(process)
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

        let r = RCIOResult.failure("read failed (tried: \(tried.joined(separator: ", ")))",
                                   diagnostic: lastDiag,
                                   duration: -start.timeIntervalSinceNow)
        appendLog(op: "read", path: path, result: r)
        return (nil, r)
    }

    /// Write data using the best available method.
    /// Always call from a background queue.
    @discardableResult
    func write(path: String, data: Data) -> RCIOResult {
        let start = Date()

        // Tier 1: direct (no O_CREAT — only for existing files at this tier)
        let existsDirect = FileManager.default.fileExists(atPath: path)
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
        let targeted = rcBestProcess(for: path)
        var tried: [String] = []
        var lastDiag = "direct \(existsDirect ? "failed errno \(errno)" : "skipped (new file)"); vfs \(mgr.vfsready ? "failed" : "not ready")"

        for process in ([targeted] + Self.fallbackOrder.filter { $0 != targeted }) {
            tried.append(process)
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

        let r = RCIOResult.failure("write failed (tried: \(tried.joined(separator: ", ")))",
                                   diagnostic: lastDiag,
                                   duration: -start.timeIntervalSinceNow)
        appendLog(op: "write", path: path, result: r)
        return r
    }

    // MARK: - RemoteCall I/O primitives

    /// Execute open/read/close inside `rc` and pull bytes back via remoteRead.
    private func rcRead(rc: RemoteCall, path: String, maxSize: Int) -> Data? {
        let pathBytes = Array((path + "\0").utf8)
        let pathLen   = pathBytes.count

        // Write path into the pre-allocated trojanMem page (4096 bytes)
        // trojanMem is always available once RC is initialised
        let trojanMem = rc.trojanMem
        guard trojanMem != 0 else { return nil }

        pathBytes.withUnsafeBytes { rc.remote_write(trojanMem, from: $0.baseAddress, size: UInt64(pathLen)) }

        // open(path, O_RDONLY, 0) — executed in target process context
        let fd = callIn(rc: rc, name: "open", args: [trojanMem, 0, 0])
        let fdInt = Int32(bitPattern: UInt32(fd & 0xFFFFFFFF))
        guard fdInt >= 0 else { return nil }

        defer { _ = callIn(rc: rc, name: "close", args: [fd]) }

        // Allocate a read buffer in the remote process for the payload
        let remoteBuf = callIn(rc: rc, name: "mmap", args: [
            0, UInt64(maxSize), 3 /* PROT_RW */, 0x1002 /* MAP_PRIVATE|MAP_ANON */,
            UInt64(bitPattern: Int64(-1)), 0
        ])
        guard remoteBuf != 0, remoteBuf != UInt64(bitPattern: -1) else { return nil }
        defer { _ = callIn(rc: rc, name: "munmap", args: [remoteBuf, UInt64(maxSize)]) }

        let n = callIn(rc: rc, name: "read", args: [fd, remoteBuf, UInt64(maxSize)])
        guard n > 0 else { return nil }

        // Pull bytes from remote into lara's address space
        var local = [UInt8](repeating: 0, count: Int(n))
        let ok = local.withUnsafeMutableBytes { rc.remoteRead(remoteBuf, to: $0.baseAddress, size: n) }
        return ok ? Data(local) : nil
    }

    /// Execute open/write/close inside `rc` after pushing bytes via remote_write.
    /// Returns (success, bytesWritten, diagnostic).
    private func rcWrite(rc: RemoteCall, path: String, data: Data) -> (Bool, Int, String) {
        let pathBytes = Array((path + "\0").utf8)
        let pathLen   = pathBytes.count

        let trojanMem = rc.trojanMem
        guard trojanMem != 0 else { return (false, 0, "trojanMem is 0") }

        // Path into trojanMem
        pathBytes.withUnsafeBytes { rc.remote_write(trojanMem, from: $0.baseAddress, size: UInt64(pathLen)) }

        // Allocate write buffer in remote — data can be arbitrarily large
        let dataLen = data.count
        let remoteBuf = callIn(rc: rc, name: "mmap", args: [
            0, UInt64(dataLen), 3, 0x1002,
            UInt64(bitPattern: Int64(-1)), 0
        ])
        guard remoteBuf != 0, remoteBuf != UInt64(bitPattern: -1) else {
            return (false, 0, "mmap failed for payload")
        }
        defer { _ = callIn(rc: rc, name: "munmap", args: [remoteBuf, UInt64(dataLen)]) }

        // Push data into remote memory
        data.withUnsafeBytes { rc.remote_write(remoteBuf, from: $0.baseAddress, size: UInt64(dataLen)) }

        // O_WRONLY | O_CREAT | O_TRUNC = 0x601
        let fd = callIn(rc: rc, name: "open", args: [trojanMem, 0x601, 0o644])
        let fdInt = Int32(bitPattern: UInt32(fd & 0xFFFFFFFF))
        guard fdInt >= 0 else {
            return (false, 0, "open() returned \(fdInt)")
        }

        let written = callIn(rc: rc, name: "write", args: [fd, remoteBuf, UInt64(dataLen)])
        _ = callIn(rc: rc, name: "close", args: [fd])

        let writtenInt = Int(written)
        if writtenInt == dataLen {
            return (true, writtenInt, "open+write+close ok")
        }
        return (false, writtenInt, "write short \(writtenInt)/\(dataLen)")
    }

    // MARK: - Process routing

    /// Maps a path to the process most likely to have the required MAC context.
    func rcBestProcess(for path: String) -> String {
        switch true {
        case path.hasPrefix("/private/var/db/MobileIdentityData"),
             path.hasPrefix("/var/db/MobileIdentityData"):
            return "mobileidentityd"

        case path.hasPrefix("/private/var/Keychains"),
             path.hasPrefix("/var/Keychains"):
            return "securityd"

        case path.hasPrefix("/private/var/db/DPLA"),
             path.hasPrefix("/var/db/DPLA"),
             path.hasPrefix("/private/var/mobile/Library/DataAccess"),
             path.hasPrefix("/var/mobile/Library/DataAccess"):
            return "dataaccessd"

        case path.hasPrefix("/private/var/mobile/Library/Media"),
             path.hasPrefix("/var/mobile/Library/Media"),
             path.hasPrefix("/private/var/mobile/Media"),
             path.hasPrefix("/var/mobile/Media"):
            return "mediaserverd"

        case path.hasPrefix("/private/var/root"),
             path.hasPrefix("/var/root"),
             path.hasPrefix("/private/var/db"),
             path.hasPrefix("/var/db"):
            // configd runs as root — handles remaining /db and /root paths
            return "configd"

        default:
            // SpringBoard (mobile uid) covers /var/mobile/**, /var/containers/**
            return "SpringBoard"
        }
    }

    // MARK: - Generic RC call helper

    /// Calls a named libc symbol inside an RC instance.
    /// dlsym resolves in lara's address space; the pointer is valid in the target
    /// because all processes share the dyld shared cache at the same addresses.
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

    /// Lists a directory.
    /// Tier order: RC (accurate, uses real process credentials) →
    ///             FileManager (fast, post-sbx) → VFS (last resort, known path bugs)
    func listDir(path: String) -> (entries: [(name: String, isDir: Bool, size: Int64)], source: String) {

        // Tier 1: RemoteCall — opendir/readdir/closedir in a routed process.
        // Goes first because VFS has path-resolution bugs (e.g. returns root entries
        // for /private/var, marks files as dirs, infinite symlink loops).
        // Only uses processes that are ALREADY ready — never triggers lazy init here.
        let best = rcBestProcess(for: path)
        var candidates = [best]
        for proc in Self.fallbackOrder where proc != best { candidates.append(proc) }
        for proc in candidates {
            if let items = rcListDirIn(path: path, process: proc) {
                mgr.logmsg("(rcio) listDir \(path) via \(proc): \(items.count) entries")
                let enriched = items.map { (name: $0.name, isDir: $0.isDir, size: Int64(-1)) }
                return (enriched, "rc:\(proc)")
            }
        }

        // Tier 2: FileManager (post-sbx-escape, fast for accessible paths)
        let fm = FileManager.default
        if let names = try? fm.contentsOfDirectory(atPath: path) {
            let entries = names.sorted().map { name -> (String, Bool, Int64) in
                let full = (path == "/" ? "" : path) + "/" + name
                var isDir: ObjCBool = false
                fm.fileExists(atPath: full, isDirectory: &isDir)
                let size = (try? fm.attributesOfItem(atPath: full)[.size] as? Int64) ?? -1
                return (name, isDir.boolValue, size ?? -1)
            }
            return (entries, "filemanager")
        }

        // Tier 3: VFS — last resort only; known to return incorrect entries for some
        // paths and mark files as directories.
        if mgr.vfsready, let items = mgr.vfslistdir(path: path) {
            let enriched = items.map { (name: $0.name, isDir: $0.isDir,
                                        size: $0.isDir ? -1 : mgr.vfssize(path: path + "/" + $0.name)) }
            return (enriched, "vfs")
        }

        return ([], "failed")
    }

    // MARK: - RC directory listing

    /// opendir/readdir/closedir inside `process`. Only uses pool entries that are
    /// already ready — does NOT trigger lazy initialisation.
    private func rcListDirIn(path: String, process: String) -> [(name: String, isDir: Bool)]? {
        poolLock.lock()
        let state = pool[process]?.state
        let rc    = pool[process]?.rc
        poolLock.unlock()
        guard case .ready = state, let rc else { return nil }

        let pathBytes = Array((path + "\0").utf8)
        let trojanMem = rc.trojanMem
        guard trojanMem != 0 else { return nil }

        pathBytes.withUnsafeBytes { rc.remote_write(trojanMem, from: $0.baseAddress, size: UInt64(pathBytes.count)) }

        let dirPtr = callIn(rc: rc, name: "opendir", args: [trojanMem])
        guard dirPtr != 0 else { return nil }
        defer { _ = callIn(rc: rc, name: "closedir", args: [dirPtr]) }

        // Darwin struct dirent (sys/dirent.h):
        //   offset  0: d_ino      UInt64
        //   offset  8: d_seekoff  UInt64
        //   offset 16: d_reclen   UInt16
        //   offset 18: d_namlen   UInt16
        //   offset 20: d_type     UInt8   (DT_DIR=4, DT_REG=8, DT_LNK=10)
        //   offset 21: d_name     char[]
        let direntReadSize: UInt64 = 21 + 256

        var result: [(name: String, isDir: Bool)] = []

        while true {
            let direntPtr = callIn(rc: rc, name: "readdir", args: [dirPtr])
            guard direntPtr != 0 else { break }

            var buf = [UInt8](repeating: 0, count: Int(direntReadSize))
            let ok = buf.withUnsafeMutableBytes { ptr in
                rc.remoteRead(direntPtr, to: ptr.baseAddress, size: direntReadSize)
            }
            guard ok else { continue }

            let namlen = Int(UInt16(buf[18]) | (UInt16(buf[19]) << 8))
            let dtype  = buf[20]
            guard namlen > 0, 21 + namlen <= buf.count else { continue }

            let nameBytes = Array(buf[21..<(21 + namlen)])
            guard let name = String(bytes: nameBytes, encoding: .utf8),
                  name != ".", name != ".." else { continue }

            result.append((name: name, isDir: dtype == 4))
        }

        guard !result.isEmpty else { return nil }
        return result.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    // MARK: - Delete

    /// Delete a file or empty directory using the best available method.
    func delete(path: String) -> RCIOResult {
        let start = Date()

        // Tier 1: direct via FileManager
        if (try? FileManager.default.removeItem(atPath: path)) != nil {
            let r = RCIOResult(ok: true, tier: .direct, process: nil, bytes: 0,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (direct delete)",
                               diagnostic: "FileManager.removeItem succeeded")
            appendLog(op: "delete", path: path, result: r)
            return r
        }

        // Tier 2: VFS overwrite (not applicable for delete — skip)

        // Tier 3: RemoteCall unlink/rmdir
        let best = rcBestProcess(for: path)
        var candidates = [best]
        for proc in Self.fallbackOrder where proc != best { candidates.append(proc) }

        for proc in candidates {
            let (ok, diag) = rcDeleteIn(path: path, process: proc)
            if ok {
                let r = RCIOResult(ok: true, tier: .remoteCall, process: proc, bytes: 0,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (rc:\(proc) deleted)",
                                   diagnostic: diag)
                appendLog(op: "delete", path: path, result: r)
                return r
            }
        }

        let r = RCIOResult.failure("delete failed (tried: \(candidates.joined(separator: ", ")))",
                                   duration: -start.timeIntervalSinceNow)
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
        let trojanMem = rc.trojanMem
        guard trojanMem != 0 else { return (false, "trojanMem is 0") }

        pathBytes.withUnsafeBytes { rc.remote_write(trojanMem, from: $0.baseAddress, size: UInt64(pathBytes.count)) }

        // Try unlink (files), then rmdir (empty dirs)
        let ul = Int32(bitPattern: UInt32(callIn(rc: rc, name: "unlink", args: [trojanMem]) & 0xFFFFFFFF))
        if ul == 0 { return (true, "\(process) unlink ok") }

        let rd = Int32(bitPattern: UInt32(callIn(rc: rc, name: "rmdir", args: [trojanMem]) & 0xFFFFFFFF))
        if rd == 0 { return (true, "\(process) rmdir ok") }

        return (false, "unlink errno=\(ul) rmdir errno=\(rd)")
    }

    // MARK: - Move / Rename

    /// Rename or move a file/directory using the best available method.
    func move(from srcPath: String, to dstPath: String) -> RCIOResult {
        let start = Date()

        // Tier 1: FileManager
        if (try? FileManager.default.moveItem(atPath: srcPath, toPath: dstPath)) != nil {
            let r = RCIOResult(ok: true, tier: .direct, process: nil, bytes: 0,
                               duration: -start.timeIntervalSinceNow,
                               message: "ok (direct move)",
                               diagnostic: "FileManager.moveItem succeeded")
            appendLog(op: "move", path: srcPath, result: r)
            return r
        }

        // Tier 2: RemoteCall rename(2) — pack both paths into trojanMem consecutively
        let best = rcBestProcess(for: srcPath)
        var candidates = [best]
        for proc in Self.fallbackOrder where proc != best { candidates.append(proc) }

        for proc in candidates {
            poolLock.lock()
            let state = pool[proc]?.state
            let rc    = pool[proc]?.rc
            poolLock.unlock()
            guard case .ready = state, let rc else { continue }

            let trojanMem = rc.trojanMem
            guard trojanMem != 0 else { continue }

            let srcBytes = Array((srcPath + "\0").utf8)
            let dstBytes = Array((dstPath + "\0").utf8)
            let srcLen   = UInt64(srcBytes.count)

            srcBytes.withUnsafeBytes { rc.remote_write(trojanMem, from: $0.baseAddress, size: srcLen) }
            let dstAddr = trojanMem + srcLen
            dstBytes.withUnsafeBytes { rc.remote_write(dstAddr, from: $0.baseAddress, size: UInt64(dstBytes.count)) }

            let ret = Int32(bitPattern: UInt32(callIn(rc: rc, name: "rename", args: [trojanMem, dstAddr]) & 0xFFFFFFFF))
            if ret == 0 {
                let r = RCIOResult(ok: true, tier: .remoteCall, process: proc, bytes: 0,
                                   duration: -start.timeIntervalSinceNow,
                                   message: "ok (rc:\(proc) renamed)",
                                   diagnostic: "\(proc) rename ok")
                appendLog(op: "move", path: srcPath, result: r)
                return r
            }
        }

        let r = RCIOResult.failure("move failed", duration: -start.timeIntervalSinceNow)
        appendLog(op: "move", path: srcPath, result: r)
        return r
    }

    // MARK: - Private helpers

    private func markInitializing(process: String) {
        poolLock.lock()
        pool[process] = RCPoolEntry(process: process, state: .initializing, rc: nil)
        poolLock.unlock()
        DispatchQueue.main.async { self.objectWillChange.send() }
    }

    private func markFailed(process: String, reason: String) {
        poolLock.lock()
        pool[process] = RCPoolEntry(process: process, state: .failed(reason: reason), rc: nil)
        poolLock.unlock()
        DispatchQueue.main.async { self.objectWillChange.send() }
        mgr.logmsg("(rcio) \(process) failed: \(reason)")
    }

    private func appendLog(op: String, path: String, result: RCIOResult) {
        let entry = RCIOLogEntry(timestamp: Date(), operation: op, path: path, result: result)
        DispatchQueue.main.async {
            self.log.insert(entry, at: 0)
            if self.log.count > 200 { self.log = Array(self.log.prefix(200)) }
        }
    }
}

// MARK: - Convenience formatters

extension Int64 {
    var fileSizeString: String {
        guard self >= 0 else { return "—" }
        if self < 1024 { return "\(self) B" }
        if self < 1024 * 1024 { return String(format: "%.1f KB", Double(self) / 1024) }
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
