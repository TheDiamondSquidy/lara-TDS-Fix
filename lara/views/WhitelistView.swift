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

    private let files: [wlfile] = [
        .init(name: "Rejections.plist", path: "/private/var/db/MobileIdentityData/Rejections.plist"),
        .init(name: "AuthListBannedUpps.plist", path: "/private/var/db/MobileIdentityData/AuthListBannedUpps.plist"),
        .init(name: "AuthListBannedCdHashes.plist", path: "/private/var/db/MobileIdentityData/AuthListBannedCdHashes.plist"),
    ]

    @State private var contents: [String: String] = [:]
    @State private var status: String?
    @State private var patching = false

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
                    .disabled(!mgr.sbxready || patching)
                } header: {
                    Text("Actions")
                } footer: {
                    Text("Overwrites MobileIdentityData blacklist files with an empty plist.")
                }

                ForEach(files) { f in
                    Section {
                        ScrollView {
                            Text(contents[f.path] ?? "(not loaded)")
                                .font(.system(size: 13, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        .frame(minHeight: 120)
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
        var next: [String: String] = [:]
        for f in files {
            guard let data = sbxread(path: f.path, maxSize: 2 * 1024 * 1024) else {
                next[f.path] = "(failed to read)"
                continue
            }
            next[f.path] = render(data: data)
        }
        contents = next
    }

    private func patchall() {
        guard mgr.sbxready else {
            status = "sandbox escape not ready"
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

    private func sbxread(path: String, maxSize: Int) -> Data? {
        do {
            let url = URL(fileURLWithPath: path)
            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            return data.count > maxSize ? data.prefix(maxSize) : data
        } catch {
            return nil
        }
    }

    /// Writes data to `path` by first writing to a temp file in the same
    /// directory and then atomically renaming it into place. This avoids
    /// opening the protected inode directly with O_TRUNC, which is what
    /// causes EPERM on files guarded by mobileidentityd on hybrid jailbreaks.
    private func sbxwrite(path: String, data: Data) -> String {
        let tmp = path + ".laratmp"

        // Write payload to the temp file
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

        // Atomically rename the temp file over the target.
        // rename(2) operates at the directory level and bypasses the guarded
        // inode, succeeding where O_TRUNC on the original path would not.
        if rename(tmp, path) == 0 {
            return "ok (\(written) bytes via rename)"
        }

        // Rename failed — clean up and fall through to VFS
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
        if data.count > maxBytes {
            return hex + "\n... (\(data.count) bytes total)"
        }
        return hex
    }
}
