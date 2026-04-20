//
//  WhitelistView.swift
//  lara
//
//  Created by ruter on 29.03.26.
//  modified and fixed by claude, implemented by TheDiamondSquidy
//
//  Write notes:
//  - Direct write works post-sbx-escape for most /var paths
//  - VFS overwrite works for existing inodes only (no new file creation)
//  - Creating new files in /private/var/db/MobileIdentityData/ requires
//    mobileidentityd's MAC context — needs remotecall, not wired here yet
//  - On a clean device the Banned plists simply don't exist, so patch is
//    disabled until a refresh finds them

import SwiftUI
import Darwin

struct WhitelistView: View {
    @ObservedObject private var mgr = laramgr.shared

    private struct wlfile: Identifiable {
        let id = UUID()
        let name: String
        let path: String
    }

    private enum ReadResult {
        case notPresent      // file absent or empty plist — device is clean
        case content(String) // file present with meaningful content
        case readError(String)
    }

    private let files: [wlfile] = [
        .init(name: "Rejections.plist",            path: "/private/var/db/MobileIdentityData/Rejections.plist"),
        .init(name: "AuthListBannedUpps.plist",     path: "/private/var/db/MobileIdentityData/AuthListBannedUpps.plist"),
        .init(name: "AuthListBannedCdHashes.plist", path: "/private/var/db/MobileIdentityData/AuthListBannedCdHashes.plist"),
    ]

    @State private var results: [String: ReadResult] = [:]
    @State private var status: String?
    @State private var working = false

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
                        if working {
                            HStack { ProgressView(); Text("Working...") }
                        } else {
                            Text("Refresh")
                        }
                    }
                    .disabled(!mgr.sbxready || working)

                    Button("Patch (Empty Plist)") {
                        patchall()
                    }
                    .disabled(!mgr.sbxready || working || !anyFilePresent)
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
                if mgr.sbxready { loadall() }
            }
        }
    }

    // MARK: - Actions

    private func loadall() {
        guard mgr.sbxready else { status = "sandbox escape not ready"; return }
        working = true
        defer { working = false }
        var next: [String: ReadResult] = [:]
        for f in files { next[f.path] = read(path: f.path) }
        results = next
    }

    private func patchall() {
        guard mgr.sbxready, anyFilePresent else {
            status = "nothing to patch — no blacklist entries present"
            return
        }
        working = true
        defer { working = false }

        guard let empty = try? PropertyListSerialization.data(fromPropertyList: [:], format: .xml, options: 0) else {
            status = "failed to build empty plist"
            return
        }

        var failures: [String] = []
        for f in files {
            guard case .content = results[f.path] else { continue }
            let result = write(path: f.path, data: empty)
            if !result.hasPrefix("ok") { failures.append("\(f.name): \(result)") }
        }

        status = failures.isEmpty ? "Patched all files!" : "Failed: \(failures.joined(separator: ", "))"
        loadall()
    }

    // MARK: - I/O

    /// Reads a file, trying direct access then VFS.
    /// Returns .notPresent when the file is absent or its plist is empty —
    /// an empty plist is indistinguishable from no ban having been recorded.
    private func read(path: String) -> ReadResult {
        // Check existence via both direct stat and VFS before attempting a read
        let exists = FileManager.default.fileExists(atPath: path)
            || (mgr.vfsready && mgr.vfsread(path: path, maxSize: 1) != nil)
        guard exists else { return .notPresent }

        // Attempt 1: direct read (works post-sbx-escape for most paths)
        let data: Data?
        if let d = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) {
            data = d
        } else if mgr.vfsready {
            // Attempt 2: VFS — confirmed working for this directory
            data = mgr.vfsread(path: path, maxSize: 2 * 1024 * 1024)
        } else {
            data = nil
        }

        guard let data else {
            return .readError("errno=\(errno) \(String(cString: strerror(errno)))\(mgr.vfsready ? " | vfs returned nil" : " | vfs not ready")")
        }

        // An empty plist means no bans — treat same as absent
        if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) {
            let isEmpty = (plist as? [AnyHashable: Any])?.isEmpty == true
                       || (plist as? [Any])?.isEmpty == true
            if isEmpty { return .notPresent }
        }

        return .content(render(data: data))
    }

    /// Writes data, trying direct I/O then VFS overwrite.
    /// Both only work on existing inodes — creating new files in
    /// MobileIdentityData requires remotecall into mobileidentityd.
    private func write(path: String, data: Data) -> String {
        // Attempt 1: direct write (post-sbx-escape)
        let fd = open(path, O_WRONLY | O_TRUNC, 0o644)   // no O_CREAT — we only patch existing files
        if fd != -1 {
            let n = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            close(fd)
            if n == data.count { return "ok (\(n) bytes direct)" }
        }

        // Attempt 2: VFS overwrite (existing inodes only, confirmed working in this dir)
        guard mgr.vfsready else {
            return "open failed: errno=\(errno) \(String(cString: strerror(errno))) | vfs not ready"
        }
        let ok = mgr.vfsoverwritewithdata(target: path, data: data)
        return ok ? "ok (vfs overwrite)" : "direct and vfs both failed for \(path)"
    }

    // MARK: - Rendering

    private func render(data: Data) -> String {
        if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
           let xmlData = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0),
           let xml = String(data: xmlData, encoding: .utf8) { return xml }
        if let s = String(data: data, encoding: .utf8) { return s }
        let cap = min(data.count, 4096)
        let hex = data.prefix(cap).map { String(format: "%02x", $0) }.joined(separator: " ")
        return data.count > cap ? hex + "\n... (\(data.count) bytes total)" : hex
    }
}
