//
//  WhitelistView.swift
//  lara
//
//  Created by ruter on 29.03.26.
//  modified and fixed by claude, implemented by TheDiamondSquidy
//
import SwiftUI
import Darwin

struct WhitelistView: View {
    @ObservedObject private var mgr = laramgr.shared

    private struct wlfile: Identifiable {
        let id = UUID()
        let name: String
        let path: String
    }

    /// The result of attempting to read a blacklist file.
    private enum ReadResult {
        case notPresent          // file doesn't exist or is empty — device is clean
        case content(String)     // file exists and has meaningful content
        case readError(String)   // file exists but couldn't be read
    }

    private let files: [wlfile] = [
        .init(name: "Rejections.plist",            path: "/private/var/db/MobileIdentityData/Rejections.plist"),
        .init(name: "AuthListBannedUpps.plist",     path: "/private/var/db/MobileIdentityData/AuthListBannedUpps.plist"),
        .init(name: "AuthListBannedCdHashes.plist", path: "/private/var/db/MobileIdentityData/AuthListBannedCdHashes.plist"),
    ]

    @State private var results: [String: ReadResult] = [:]
    @State private var status: String?
    @State private var patching = false

    /// True only if at least one blacklist file exists and has content.
    private var anyFilePresent: Bool {
        results.values.contains { if case .content = $0 { return true }; return false }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Button {
                        loadall()
                    } label: {
                        if patching {
                            HStack {
                                ProgressView()
                                Text("Working...")
                            }
                        } else {
                            Text("Refresh")
                        }
                    }
                    .disabled(!mgr.sbxready || patching)

                    Button("Patch (Empty Plist)") {
                        patchall()
                    }
                    .disabled(!mgr.sbxready || patching || !anyFilePresent)
                } header: {
                    Text("Actions")
                } footer: {
                    if !results.isEmpty && !anyFilePresent {
                        Text("No blacklist entries found — this device does not appear to be flagged.")
                    } else {
                        Text("Overwrites MobileIdentityData blacklist files with an empty plist.")
                    }
                }

                ForEach(files) { f in
                    Section {
                        switch results[f.path] {
                        case .none:
                            Text("(not loaded)")
                                .font(.system(size: 13, design: .monospaced))
                                .foregroundColor(.secondary)

                        case .notPresent:
                            HStack(spacing: 8) {
                                Image(systemName: "checkmark.shield.fill")
                                    .foregroundColor(.green)
                                Text("Not present — device is not blacklisted")
                                    .font(.system(size: 13, design: .monospaced))
                                    .foregroundColor(.green)
                            }

                        case .content(let text):
                            ScrollView {
                                Text(text)
                                    .font(.system(size: 13, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                            .frame(minHeight: 120)

                        case .readError(let reason):
                            VStack(alignment: .leading, spacing: 4) {
                                Text("(failed to read)")
                                    .font(.system(size: 13, design: .monospaced))
                                    .foregroundColor(.red)
                                Text(reason)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.secondary)
                                    .textSelection(.enabled)
                            }
                        }
                    } header: {
                        Text(f.name)
                    } footer: {
                        Text(f.path)
                    }
                }
            }
            .navigationTitle("Whitelist")
            .alert("Status", isPresented: .constant(status != nil)) {
                Button("OK") { status = nil }
            } message: {
                Text(status ?? "")
            }
            .onAppear {
                if mgr.sbxready {
                    loadall()
                }
            }
        }
    }

    // MARK: - Actions

    private func loadall() {
        guard mgr.sbxready else {
            status = "sandbox escape not ready"
            return
        }
        patching = true
        defer { patching = false }
        var next: [String: ReadResult] = [:]
        for f in files {
            next[f.path] = sbxread(path: f.path, maxSize: 2 * 1024 * 1024)
        }
        results = next
    }

    private func patchall() {
        guard mgr.sbxready, anyFilePresent else {
            status = "nothing to patch — no blacklist entries present"
            return
        }
        patching = true
        defer { patching = false }

        guard let data = try? PropertyListSerialization.data(
            fromPropertyList: [:],
            format: .xml,
            options: 0
        ) else {
            status = "failed to build empty plist"
            return
        }

        var failures: [String] = []

        for f in files {
            guard case .content = results[f.path] else { continue }
            let result = sbxwrite(path: f.path, data: data)
            if !result.hasPrefix("ok") {
                failures.append("\(f.name): \(result)")
            }
        }

        if failures.isEmpty {
            status = "Patched all files!"
        } else {
            status = "Failed to patch: \(failures.joined(separator: ", "))"
        }

        loadall()
    }

    // MARK: - I/O

    /// Reads a file and classifies the result:
    /// - `.notPresent` if the file doesn't exist OR if its plist is empty
    ///   (an empty Rejections.plist means no rejections have been recorded,
    ///   which is indistinguishable from the file not existing in terms of
    ///   whether the device is blacklisted)
    /// - `.content` if the file exists and contains meaningful data
    /// - `.readError` if the file exists but couldn't be read
    private func sbxread(path: String, maxSize: Int) -> ReadResult {
        let exists = FileManager.default.fileExists(atPath: path)
            || (mgr.vfsready && vfsExists(path: path))

        guard exists else {
            return .notPresent
        }

        // Attempt 1: direct read
        let data: Data?
        if let d = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) {
            data = d.count > maxSize ? d.prefix(maxSize) : d
        } else if mgr.vfsready {
            // Attempt 2: VFS fallback
            data = mgr.vfsread(path: path, maxSize: maxSize)
        } else {
            data = nil
        }

        guard let data = data else {
            let errDesc = String(cString: strerror(errno))
            return .readError("errno=\(errno) \(errDesc)\(mgr.vfsready ? " | vfs returned nil" : " | vfs not ready")")
        }

        // Treat an empty plist (empty dict or empty array) the same as the
        // file not existing — a Rejections.plist with no entries is not a
        // sign the device is blacklisted, just that mobileidentityd created
        // the file as bookkeeping without recording any actual bans.
        if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) {
            let isEmpty = (plist as? [AnyHashable: Any])?.isEmpty == true
                       || (plist as? [Any])?.isEmpty == true
            if isEmpty {
                return .notPresent
            }
        }

        return .content(render(data: data))
    }

    /// Lightweight existence check via VFS for paths not reachable by FileManager.
    private func vfsExists(path: String) -> Bool {
        mgr.vfsread(path: path, maxSize: 1) != nil
    }

    /// Writes data using a temp file + atomic rename to avoid O_TRUNC on
    /// guarded inodes. Falls back to VFS overwrite if rename fails.
    private func sbxwrite(path: String, data: Data) -> String {
        let tmp = path + ".laratmp"

        let fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        guard fd != -1 else {
            return vfsfallback(
                path: path, data: data,
                reason: "open tmp failed: errno=\(errno) \(String(cString: strerror(errno)))"
            )
        }

        let written = data.withUnsafeBytes { ptr in
            write(fd, ptr.baseAddress, ptr.count)
        }
        close(fd)

        guard written != -1 else {
            unlink(tmp)
            return vfsfallback(
                path: path, data: data,
                reason: "write tmp failed: errno=\(errno) \(String(cString: strerror(errno)))"
            )
        }

        if rename(tmp, path) == 0 {
            return "ok (\(written) bytes via rename)"
        }

        let renameErrno = errno
        unlink(tmp)
        return vfsfallback(
            path: path, data: data,
            reason: "rename failed: errno=\(renameErrno) \(String(cString: strerror(renameErrno)))"
        )
    }

    private func vfsfallback(path: String, data: Data, reason: String) -> String {
        guard mgr.vfsready else {
            return reason + " | vfs not ready"
        }
        let ok = mgr.vfsoverwritewithdata(target: path, data: data)
        return ok ? "ok (vfs overwrite)" : reason + " | vfs overwrite failed"
    }

    // MARK: - Rendering

    private func render(data: Data) -> String {
        if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
           let xmlData = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0),
           let xml = String(data: xmlData, encoding: .utf8) {
            return xml
        }
        if let s = String(data: data, encoding: .utf8) {
            return s
        }
        let maxBytes = min(data.count, 4096)
        let hex = data.prefix(maxBytes).map { String(format: "%02x", $0) }.joined(separator: " ")
        return data.count > maxBytes ? hex + "\n... (\(data.count) bytes total)" : hex
    }
}
