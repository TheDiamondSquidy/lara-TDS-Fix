//
//  FileManagerView.swift
//  lara
//
//  File manager backed by RemoteFileIO.
//  All operations display tier, process, timing, and diagnostic strings.
//

import SwiftUI
import UniformTypeIdentifiers
import Darwin

// MARK: - FileManagerView

struct FileManagerView: View {
    @ObservedObject private var mgr  = laramgr.shared
    @ObservedObject private var rcio = RemoteFileIO.shared

    @State private var path: String = "/private/var"
    @State private var entries: [(name: String, isDir: Bool, size: Int64)] = []
    @State private var listSource: String = ""
    @State private var loading = false
    @State private var status: String?

    // File operation state
    @State private var selectedFile: String?          // path for picker overwrite
    @State private var showPicker = false
    @State private var pickedData: Data?
    @State private var pickedName: String?

    // Preview
    @State private var previewPath: String?
    @State private var previewResult: (data: Data?, result: RCIOResult)?
    @State private var showPreview = false

    // Debug panel
    @State private var showDebug = true
    @State private var showLog = false
    @State private var showPool = true
    @State private var lastOpResult: RCIOResult?

    // Delete
    @State private var deleteTarget: String?
    @State private var showDeleteConfirm = false

    // Copy / Paste
    @State private var copyBuffer: (path: String, name: String)?

    // Rename
    @State private var renameTarget: String?
    @State private var renameDest: String = ""
    @State private var showRename = false

    var body: some View {
        VStack(spacing: 0) {
            breadcrumb
            Divider()
            if showDebug { debugPanel }
            fileList
        }
        .navigationTitle("File Manager")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if let buf = copyBuffer {
                    Button {
                        handlePaste(buf)
                    } label: {
                        Label("Paste \(buf.name)", systemImage: "doc.on.clipboard.fill")
                            .foregroundColor(.mint)
                            .font(.system(size: 12, design: .monospaced))
                    }
                }

                Button {
                    withAnimation { showDebug.toggle() }
                } label: {
                    Image(systemName: showDebug ? "ant.fill" : "ant")
                        .foregroundColor(showDebug ? .orange : .secondary)
                }

                Button {
                    showPicker = true
                    selectedFile = nil
                } label: {
                    Image(systemName: "plus")
                }
                .disabled(!mgr.dsready)
            }
        }
        .alert("Status", isPresented: .constant(status != nil)) {
            Button("OK") { status = nil }
        } message: { Text(status ?? "") }
        .alert("Delete", isPresented: $showDeleteConfirm, presenting: deleteTarget) { target in
            Button("Delete", role: .destructive) { handleDelete(target) }
            Button("Cancel", role: .cancel) {}
        } message: { target in
            Text("Permanently delete \(URL(fileURLWithPath: target).lastPathComponent)?")
        }
        .alert("Rename", isPresented: $showRename, presenting: renameTarget) { target in
            TextField("New name", text: $renameDest)
            Button("Rename") {
                let dest = (path == "/" ? "" : path) + "/" + renameDest
                handleMove(from: target, to: dest)
            }
            Button("Cancel", role: .cancel) {}
        } message: { target in
            Text("Rename \(URL(fileURLWithPath: target).lastPathComponent)")
        }
        .sheet(isPresented: $showPicker) {
            RCFilePicker(data: $pickedData, filename: $pickedName)
        }
        .sheet(isPresented: $showPreview) {
            if let path = previewPath, let res = previewResult {
                FilePreviewSheet(path: path, data: res.data, result: res.result)
            }
        }
        .onChange(of: pickedData) { data in
            guard let data else { return }
            pickedData = nil
            handlePickedData(data)
        }
        .onAppear { loadEntries() }
    }

    // MARK: - Breadcrumb

    private var breadcrumb: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 2) {
                Button("/") { navigate(to: "/") }
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.blue)

                ForEach(Array(pathComponents.enumerated()), id: \.offset) { i, part in
                    Text(" / ").font(.system(size: 12, design: .monospaced)).foregroundColor(.secondary)
                    Button(part) {
                        navigate(to: "/" + pathComponents[0...i].joined(separator: "/"))
                    }
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.blue)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
        .background(Color(.secondarySystemBackground))
    }

    private var pathComponents: [String] {
        path.components(separatedBy: "/").filter { !$0.isEmpty }
    }

    // MARK: - Debug panel

    private var debugPanel: some View {
        VStack(spacing: 0) {
            // Pool status row
            HStack {
                Text("RC POOL")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(.orange)
                Spacer()
                Button(showPool ? "hide" : "show") { withAnimation { showPool.toggle() } }
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary)
                Button(showLog ? "ops" : "ops") {
                    withAnimation { showLog.toggle() }
                }
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(showLog ? .orange : .secondary)
            }
            .padding(.horizontal, 10)
            .padding(.top, 6)

            if showPool && !showLog {
                poolStatusView
            }

            if showLog {
                opLogView
            }

            // Last operation summary
            if let r = lastOpResult {
                lastOpBar(r)
            }

            // Directory list source
            if !listSource.isEmpty {
                HStack {
                    Text("dir source: \(listSource)  entries: \(entries.count)  path: \(path)")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                    Spacer()
                }
                .padding(.horizontal, 10)
                .padding(.bottom, 4)
            }

            Divider()
        }
        .background(Color(.tertiarySystemBackground))
    }

    private var poolStatusView: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(poolEntries, id: \.process) { entry in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(entry.process)
                            .font(.system(size: 9, weight: .semibold, design: .monospaced))
                            .foregroundColor(.primary)
                        Text(entry.state.description)
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundColor(stateColor(entry.state))
                        if case .failed = entry.state {
                            Button("retry") {
                                rcio.resetProc(entry.process)
                            }
                            .font(.system(size: 8, design: .monospaced))
                            .foregroundColor(.orange)
                        }
                    }
                    .padding(6)
                    .background(
                        RoundedRectangle(cornerRadius: 5)
                            .fill(stateColor(entry.state).opacity(0.1))
                            .overlay(
                                RoundedRectangle(cornerRadius: 5)
                                    .stroke(stateColor(entry.state).opacity(0.4), lineWidth: 1)
                            )
                    )
                }

                // Init buttons for uninitialized/failed
                ForEach(initCandidates, id: \.self) { process in
                    Button {
                        initProcess(process)
                    } label: {
                        Label("init \(process)", systemImage: "bolt")
                            .font(.system(size: 9, design: .monospaced))
                    }
                    .padding(6)
                    .background(
                        RoundedRectangle(cornerRadius: 5)
                            .fill(Color.blue.opacity(0.1))
                            .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.blue.opacity(0.3), lineWidth: 1))
                    )
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
        }
    }

    private var opLogView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 2) {
                if rcio.log.isEmpty {
                    Text("no operations yet")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                ForEach(rcio.log.prefix(30)) { entry in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(entry.summary)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(entry.result.ok ? .primary : .red)
                        if !entry.result.diagnostic.isEmpty {
                            Text("  ↳ \(entry.result.diagnostic)")
                                .font(.system(size: 9, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
        }
        .frame(maxHeight: 140)
    }

    @ViewBuilder
    private func lastOpBar(_ r: RCIOResult) -> some View {
        HStack {
            Circle()
                .fill(r.ok ? Color.green : Color.red)
                .frame(width: 6, height: 6)
            Text(r.message)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(r.ok ? .primary : .red)
            Spacer()
            Text(String(format: "%.0fms", r.duration * 1000))
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.secondary)
            Text(r.tier.rawValue)
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .foregroundColor(tierColor(r.tier))
                .padding(.horizontal, 4)
                .padding(.vertical, 2)
                .background(
                    RoundedRectangle(cornerRadius: 3)
                        .fill(tierColor(r.tier).opacity(0.15))
                )
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
    }

    // MARK: - File list

    private var fileList: some View {
        List {
            if loading {
                HStack { Spacer(); ProgressView(); Text("Loading...").foregroundColor(.secondary); Spacer() }
            } else if entries.isEmpty {
                Text("Empty or inaccessible")
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(.secondary)
            } else {
                // Parent dir button
                if path != "/" {
                    Button {
                        let parent = (path as NSString).deletingLastPathComponent
                        navigate(to: parent.isEmpty ? "/" : parent)
                    } label: {
                        HStack {
                            Image(systemName: "arrow.up.doc.fill").foregroundColor(.secondary).frame(width: 22)
                            Text("..").font(.system(.body, design: .monospaced))
                        }
                    }
                }

                ForEach(entries, id: \.name) { entry in
                    entryRow(entry)
                }
            }
        }
        .listStyle(.plain)
        .refreshable { loadEntries() }
    }

    @ViewBuilder
    private func entryRow(_ entry: (name: String, isDir: Bool, size: Int64)) -> some View {
        let fullPath = (path == "/" ? "" : path) + "/" + entry.name

        HStack(spacing: 10) {
            // Icon
            Image(systemName: entry.isDir ? "folder.fill" : fileIcon(for: entry.name))
                .foregroundColor(entry.isDir ? .yellow : .secondary)
                .frame(width: 22)

            // Name + size
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.name)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                if !entry.isDir {
                    Text(entry.size.fileSizeString)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            // Routed process badge for files
            if !entry.isDir {
                Text(rcio.rcBestProcess(for: fullPath))
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.orange)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 2)
                    .background(
                        RoundedRectangle(cornerRadius: 3)
                            .fill(Color.orange.opacity(0.1))
                    )
            }

            // Action buttons (files only)
            if !entry.isDir {
                Button {
                    openPreview(path: fullPath)
                } label: {
                    Image(systemName: "eye")
                }
                .buttonStyle(.borderless)
                .foregroundColor(.blue)

                Button {
                    selectedFile = fullPath
                    showPicker = true
                } label: {
                    Image(systemName: "arrow.up.doc")
                }
                .buttonStyle(.borderless)
                .foregroundColor(.orange)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            if entry.isDir { navigate(to: fullPath) }
        }
        .swipeActions(edge: .leading) {
            Button {
                UIPasteboard.general.string = fullPath
                status = "Copied path: \(fullPath)"
            } label: {
                Label("Copy Path", systemImage: "doc.on.doc")
            }
            .tint(.blue)

            Button {
                copyBuffer = (path: fullPath, name: entry.name)
                status = entry.isDir ? "Directories cannot be copied yet" : "Buffered: \(entry.name)"
            } label: {
                Label("Copy", systemImage: "doc.on.clipboard")
            }
            .tint(.mint)
            .disabled(entry.isDir)

            Button {
                renameTarget = fullPath
                renameDest = entry.name
                showRename = true
            } label: {
                Label("Rename", systemImage: "pencil")
            }
            .tint(.indigo)
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) {
                deleteTarget = fullPath
                showDeleteConfirm = true
            } label: {
                Label("Delete", systemImage: "trash")
            }

            if !entry.isDir {
                Button {
                    selectedFile = fullPath
                    showPicker = true
                } label: {
                    Label("Overwrite", systemImage: "arrow.up.doc.fill")
                }
                .tint(.orange)
            }
        }
    }

    // MARK: - Navigation and loading

    private func navigate(to newPath: String) {
        // Resolve symlinks to canonical path — on iOS /private is a circular
        // symlink to root, so without this tapping "private" builds
        // /private/private/private/... forever while VFS lists root each time.
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        let canonical = (Darwin.realpath(newPath, &buf) != nil) ? String(cString: buf) : newPath
        path = canonical
        loadEntries()
    }

    private func loadEntries() {
        // Snapshot path on the main thread before dispatching — reading @State
        // from a background thread is unsafe and returns stale values.
        let targetPath = path
        loading = true
        entries = []
        listSource = ""
        DispatchQueue.global(qos: .userInitiated).async {
            let (e, src) = rcio.listDir(path: targetPath)
            DispatchQueue.main.async {
                // Discard result if user navigated away during the fetch
                guard self.path == targetPath else { return }
                self.entries = e
                self.listSource = src
                self.loading = false
            }
        }
    }

    // MARK: - File operations

    private func handlePickedData(_ data: Data) {
        let target: String
        if let sel = selectedFile {
            target = sel
        } else {
            // New file in current directory
            let name = pickedName ?? "lara_new_\(Int(Date().timeIntervalSince1970)).bin"
            target = path + "/" + name
        }
        selectedFile = nil
        pickedName = nil

        DispatchQueue.global(qos: .userInitiated).async {
            let result = rcio.write(path: target, data: data)
            DispatchQueue.main.async {
                self.lastOpResult = result
                self.status = result.message
                if result.ok { self.loadEntries() }
            }
        }
    }

    private func openPreview(path: String) {
        previewPath = path
        previewResult = nil
        showPreview = true

        DispatchQueue.global(qos: .userInitiated).async {
            let (data, result) = rcio.read(path: path, maxSize: 256 * 1024)
            DispatchQueue.main.async {
                self.previewResult = (data, result)
                self.lastOpResult = result
            }
        }
    }

    private func handleDelete(_ path: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = rcio.delete(path: path)
            DispatchQueue.main.async {
                self.lastOpResult = result
                self.status = result.message
                if result.ok { self.loadEntries() }
            }
        }
    }

    private func handlePaste(_ buf: (path: String, name: String)) {
        // Copy file: read from source then write to current directory
        let dest = (path == "/" ? "" : path) + "/" + buf.name
        DispatchQueue.global(qos: .userInitiated).async {
            let (data, readResult) = rcio.read(path: buf.path)
            guard let data else {
                DispatchQueue.main.async { self.status = "Copy failed: \(readResult.message)" }
                return
            }
            let writeResult = rcio.write(path: dest, data: data)
            DispatchQueue.main.async {
                self.lastOpResult = writeResult
                self.status = writeResult.message
                if writeResult.ok {
                    self.copyBuffer = nil
                    self.loadEntries()
                }
            }
        }
    }

    private func handleMove(from src: String, to dst: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = rcio.move(from: src, to: dst)
            DispatchQueue.main.async {
                self.lastOpResult = result
                self.status = result.message
                if result.ok { self.loadEntries() }
            }
        }
    }

    // MARK: - RC pool helpers

    private var poolEntries: [RCPoolEntry] {
        let order = ["SpringBoard", "configd", "mobileidentityd", "securityd", "dataaccessd", "mediaserverd"]
        return order.compactMap { rcio.pool[$0] }
    }

    private var initCandidates: [String] {
        poolEntries
            .filter { if case .uninitialized = $0.state { return true }; return false }
            .map { $0.process }
    }

    private func initProcess(_ process: String) {
        guard mgr.dsready else { status = "darksword not ready"; return }
        DispatchQueue.global(qos: .userInitiated).async {
            _ = rcio.rcProc(for: process)
        }
    }

    // MARK: - Colour helpers

    private func stateColor(_ state: RCPoolEntry.State) -> Color {
        switch state {
        case .ready:         return .green
        case .initializing:  return .blue
        case .failed:        return .red
        case .uninitialized: return .secondary
        }
    }

    private func tierColor(_ tier: RCIOTier) -> Color {
        switch tier {
        case .direct:     return .green
        case .vfs:        return .blue
        case .remoteCall: return .orange
        case .failed:     return .red
        }
    }

    private func fileIcon(for name: String) -> String {
        let ext = (name as NSString).pathExtension.lowercased()
        switch ext {
        case "plist":              return "list.bullet.rectangle"
        case "png", "jpg", "jpeg", "webp", "heic": return "photo"
        case "mp4", "mov", "m4v": return "film"
        case "mp3", "m4a", "aac": return "music.note"
        case "pdf":                return "doc.richtext"
        case "dylib", "so":        return "gear"
        case "db", "sqlite":       return "cylinder"
        case "bin", "img":         return "cpu"
        default:                   return "doc"
        }
    }
}

// MARK: - File preview sheet

struct FilePreviewSheet: View {
    let path: String
    let data: Data?
    let result: RCIOResult

    @Environment(\.dismiss) private var dismiss
    @State private var viewMode: PreviewMode = .auto

    enum PreviewMode: String, CaseIterable { case auto, text, hex, plist }

    private var filename: String { URL(fileURLWithPath: path).lastPathComponent }

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Operation result banner
                resultBanner

                // Mode picker
                Picker("Mode", selection: $viewMode) {
                    ForEach(PreviewMode.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .padding()

                Divider()

                // Content
                ScrollView {
                    if let data {
                        contentView(data: data)
                            .padding()
                    } else {
                        VStack(spacing: 12) {
                            Image(systemName: "exclamationmark.triangle")
                                .font(.system(size: 40))
                                .foregroundColor(.red)
                            Text("Failed to read file")
                                .font(.headline)
                            Text(result.diagnostic)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                        }
                        .padding(40)
                    }
                }
            }
            .navigationTitle(filename)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
                if let data {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        ShareLink(item: data, preview: SharePreview(filename))
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var resultBanner: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(result.ok ? Color.green : Color.red)
                .frame(width: 7, height: 7)

            VStack(alignment: .leading, spacing: 2) {
                Text(result.message)
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                if !result.diagnostic.isEmpty && result.diagnostic != result.message {
                    Text(result.diagnostic)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 2) {
                Text(result.tier.rawValue)
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(tierBadgeColor)
                if let proc = result.process {
                    Text(proc)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                Text(String(format: "%.0fms", result.duration * 1000))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(Color(.secondarySystemBackground))
    }

    private var tierBadgeColor: Color {
        switch result.tier {
        case .direct:     return .green
        case .vfs:        return .blue
        case .remoteCall: return .orange
        case .failed:     return .red
        }
    }

    @ViewBuilder
    private func contentView(data: Data) -> some View {
        switch effectiveMode(for: data) {
        case .plist:
            if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
               let xml = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0),
               let str = String(data: xml, encoding: .utf8) {
                Text(str)
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                fallbackText(data: data)
            }

        case .text:
            fallbackText(data: data)

        case .hex:
            Text(hexDump(data: data))
                .font(.system(size: 11, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)

        case .auto:
            EmptyView() // should not reach
        }
    }

    @ViewBuilder
    private func fallbackText(data: Data) -> some View {
        if let str = String(data: data, encoding: .utf8) {
            Text(str)
                .font(.system(size: 12, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            Text(hexDump(data: data))
                .font(.system(size: 11, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func effectiveMode(for data: Data) -> PreviewMode {
        if viewMode != .auto { return viewMode }
        // Auto-detect
        if (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) != nil { return .plist }
        if String(data: data.prefix(512), encoding: .utf8) != nil { return .text }
        return .hex
    }

    private func hexDump(data: Data) -> String {
        let cap = min(data.count, 4096)
        var lines: [String] = []
        let bytes = Array(data.prefix(cap))
        stride(from: 0, to: bytes.count, by: 16).forEach { i in
            let chunk = bytes[i..<min(i + 16, bytes.count)]
            let hex   = chunk.map { String(format: "%02x", $0) }.joined(separator: " ")
            let ascii = chunk.map { $0 >= 32 && $0 < 127 ? String(UnicodeScalar($0)) : "." }.joined()
            lines.append(String(format: "%08x  %-47s  |%@|", i, hex, ascii))
        }
        if data.count > cap { lines.append("... (\(data.count) bytes total)") }
        return lines.joined(separator: "\n")
    }
}

// MARK: - File picker wrapper

private struct RCFilePicker: UIViewControllerRepresentable {
    @Binding var data: Data?
    @Binding var filename: String?

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let p = UIDocumentPickerViewController(forOpeningContentTypes: [.data, .item], asCopy: true)
        p.delegate = context.coordinator
        return p
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}
    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let parent: RCFilePicker
        init(_ p: RCFilePicker) { parent = p }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard let url = urls.first else { return }
            _ = url.startAccessingSecurityScopedResource()
            defer { url.stopAccessingSecurityScopedResource() }
            parent.data = try? Data(contentsOf: url)
            parent.filename = url.lastPathComponent
        }
    }
}
