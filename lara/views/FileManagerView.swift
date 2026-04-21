//
//  FileManagerView.swift
//  lara
//
//  File manager backed by RemoteFileIO.
//  Debug panel: compact Processes button (opens ProcessSelectorView), op log,
//  and a process override pill that routes all operations through a chosen process.
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
    @State private var selectedFile: String?
    @State private var showPicker = false
    @State private var pickedData: Data?
    @State private var pickedName: String?

    // Preview
    @State private var previewPath: String?
    @State private var previewResult: (data: Data?, result: RCIOResult)?
    @State private var showPreview = false

    // Debug panel
    @State private var showDebug   = true
    @State private var showLog     = false
    @State private var lastOpResult: RCIOResult?

    // Process selector / override
    @State private var showProcessSelector = false
    @State private var processOverride: String? = nil   // nil = auto routing

    // Delete
    @State private var deleteTarget: String?
    @State private var showDeleteConfirm = false

    // Copy / Paste
    @State private var copyBuffer: (path: String, name: String)?

    // Rename
    @State private var renameTarget: String?
    @State private var renameDest:   String = ""
    @State private var showRename    = false

    // MARK: - Body

    var body: some View {
        VStack(spacing: 0) {
            breadcrumb
            Divider()
            if showDebug { debugPanel }
            fileList
        }
        .navigationTitle("RC File Manager")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if let buf = copyBuffer {
                    Button { handlePaste(buf) } label: {
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
                    showPicker   = true
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
        .sheet(isPresented: $showProcessSelector) {
            ProcessSelectorView(
                pathContext:      path,
                selectedOverride: $processOverride
            )
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

    // MARK: - Debug panel (streamlined)

    private var debugPanel: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                // Processes button — replaces old scrolling tile pool view
                Button {
                    showProcessSelector = true
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "cpu")
                        Text(poolSummaryLabel)
                            .font(.system(size: 11, design: .monospaced))
                    }
                }
                .buttonStyle(.bordered)
                .tint(anyReady ? .green : .secondary)
                .controlSize(.mini)

                // Override indicator / auto-route label
                if let ov = processOverride {
                    Button {
                        processOverride = nil
                    } label: {
                        HStack(spacing: 3) {
                            Image(systemName: "arrow.triangle.branch")
                            Text(ov)
                                .font(.system(size: 11, design: .monospaced))
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 9))
                        }
                    }
                    .buttonStyle(.bordered)
                    .tint(.orange)
                    .controlSize(.mini)
                } else {
                    Text("→ \(rcio.rcBestProcess(for: path))")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                }

                Spacer()

                // Log toggle
                Button {
                    withAnimation { showLog.toggle() }
                } label: {
                    HStack(spacing: 3) {
                        Image(systemName: "list.bullet.rectangle")
                        if !rcio.log.isEmpty {
                            Text("\(rcio.log.count)")
                                .font(.system(size: 11, design: .monospaced))
                        }
                    }
                }
                .buttonStyle(.bordered)
                .tint(showLog ? .orange : .secondary)
                .controlSize(.mini)
            }
            .padding(.horizontal, 10)
            .padding(.top, 6)

            // Op log inline view (shown when toggled)
            if showLog {
                opLogView
            }

            // Last operation result
            if let r = lastOpResult {
                lastOpBar(r)
            }

            // Directory listing info
            if !listSource.isEmpty {
                HStack {
                    Text("src:\(listSource)  \(entries.count) entries")
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
                .lineLimit(1)
            Spacer()
            Text(String(format: "%.0fms", r.duration * 1000))
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.secondary)
            tierBadge(r.tier)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private func tierBadge(_ tier: RCIOTier) -> some View {
        let color: Color = {
            switch tier {
            case .direct:     return .green
            case .vfs:        return .blue
            case .remoteCall: return .orange
            case .failed:     return .red
            }
        }()
        Text(tier.rawValue)
            .font(.system(size: 9, weight: .semibold, design: .monospaced))
            .foregroundColor(color)
            .padding(.horizontal, 4).padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: 3).fill(color.opacity(0.15)))
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
            Image(systemName: entry.isDir ? "folder.fill" : fileIcon(for: entry.name))
                .foregroundColor(entry.isDir ? .yellow : .secondary)
                .frame(width: 22)

            VStack(alignment: .leading, spacing: 1) {
                Text(entry.name)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                if !entry.isDir {
                    HStack(spacing: 6) {
                        Text(entry.size.fileSizeString)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.secondary)
                        // Show effective process — orange if override is active
                        let effective = processOverride ?? rcio.rcBestProcess(for: fullPath)
                        Text(effective)
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundColor(processOverride != nil ? .orange : .secondary)
                            .padding(.horizontal, 3).padding(.vertical, 1)
                            .background(
                                RoundedRectangle(cornerRadius: 3)
                                    .fill((processOverride != nil ? Color.orange : Color.secondary).opacity(0.1))
                            )
                    }
                }
            }

            Spacer()

            if !entry.isDir {
                Button { openPreview(path: fullPath) } label: {
                    Image(systemName: "eye")
                }
                .buttonStyle(.borderless)
                .foregroundColor(.blue)

                Button {
                    selectedFile = fullPath
                    showPicker   = true
                } label: {
                    Image(systemName: "arrow.up.doc")
                }
                .buttonStyle(.borderless)
                .foregroundColor(.orange)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { if entry.isDir { navigate(to: fullPath) } }
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
                renameDest   = entry.name
                showRename   = true
            } label: {
                Label("Rename", systemImage: "pencil")
            }
            .tint(.indigo)
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) {
                deleteTarget      = fullPath
                showDeleteConfirm = true
            } label: {
                Label("Delete", systemImage: "trash")
            }

            if !entry.isDir {
                Button {
                    selectedFile = fullPath
                    showPicker   = true
                } label: {
                    Label("Overwrite", systemImage: "arrow.up.doc.fill")
                }
                .tint(.orange)
            }
        }
    }

    // MARK: - Navigation and loading

    private func navigate(to newPath: String) {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        let canonical = (Darwin.realpath(newPath, &buf) != nil) ? String(cString: buf) : newPath
        path = canonical
        loadEntries()
    }

    private func loadEntries() {
        let targetPath = path
        loading    = true
        entries    = []
        listSource = ""
        DispatchQueue.global(qos: .userInitiated).async {
            let (e, src) = rcio.listDir(path: targetPath)
            DispatchQueue.main.async {
                guard self.path == targetPath else { return }
                self.entries    = e
                self.listSource = src
                self.loading    = false
            }
        }
    }

    // MARK: - File operations (pass override through to rcio)

    private func handlePickedData(_ data: Data) {
        let target: String
        if let sel = selectedFile {
            target = sel
        } else {
            let name = pickedName ?? "lara_new_\(Int(Date().timeIntervalSince1970)).bin"
            target = path + "/" + name
        }
        selectedFile = nil
        pickedName   = nil

        DispatchQueue.global(qos: .userInitiated).async {
            let result = rcio.write(path: target, data: data, override: self.processOverride)
            DispatchQueue.main.async {
                self.lastOpResult = result
                self.status       = result.message
                if result.ok { self.loadEntries() }
            }
        }
    }

    private func openPreview(path: String) {
        previewPath   = path
        previewResult = nil
        showPreview   = true

        DispatchQueue.global(qos: .userInitiated).async {
            let (data, result) = rcio.read(path: path, maxSize: 256 * 1024, override: self.processOverride)
            DispatchQueue.main.async {
                self.previewResult = (data, result)
                self.lastOpResult  = result
            }
        }
    }

    private func handleDelete(_ path: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = rcio.delete(path: path)
            DispatchQueue.main.async {
                self.lastOpResult = result
                self.status       = result.message
                if result.ok { self.loadEntries() }
            }
        }
    }

    private func handlePaste(_ buf: (path: String, name: String)) {
        let dest = (path == "/" ? "" : path) + "/" + buf.name
        DispatchQueue.global(qos: .userInitiated).async {
            let (data, readResult) = rcio.read(path: buf.path, override: self.processOverride)
            guard let data else {
                DispatchQueue.main.async { self.status = "Copy failed: \(readResult.message)" }
                return
            }
            let writeResult = rcio.write(path: dest, data: data, override: self.processOverride)
            DispatchQueue.main.async {
                self.lastOpResult = writeResult
                self.status       = writeResult.message
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
                self.status       = result.message
                if result.ok { self.loadEntries() }
            }
        }
    }

    // MARK: - Pool helpers

    private var anyReady: Bool {
        rcio.pool.values.contains { $0.state.isReady }
    }

    private var poolSummaryLabel: String {
        let ready = rcio.pool.values.filter { $0.state.isReady }.count
        let total = RemoteFileIO.recommendedProcesses.count
        return "Procs \(ready)/\(total)"
    }

    // MARK: - Colour / icon helpers

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

// MARK: - File preview sheet (unchanged from original)

struct FilePreviewSheet: View {
    let path:   String
    let data:   Data?
    let result: RCIOResult

    @Environment(\.dismiss) private var dismiss
    @State private var viewMode: PreviewMode = .auto

    enum PreviewMode: String, CaseIterable { case auto, text, hex, plist }

    private var filename: String { URL(fileURLWithPath: path).lastPathComponent }

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                resultBanner
                Picker("Mode", selection: $viewMode) {
                    ForEach(PreviewMode.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .padding()
                Divider()
                ScrollView {
                    if let data {
                        contentView(data: data).padding()
                    } else {
                        VStack(spacing: 12) {
                            Image(systemName: "exclamationmark.triangle").font(.system(size: 40)).foregroundColor(.red)
                            Text("Failed to read file").font(.headline)
                            Text(result.diagnostic).font(.system(size: 12, design: .monospaced)).foregroundColor(.secondary).multilineTextAlignment(.center)
                        }.padding(40)
                    }
                }
            }
            .navigationTitle(filename)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
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
            Circle().fill(result.ok ? Color.green : Color.red).frame(width: 7, height: 7)
            VStack(alignment: .leading, spacing: 2) {
                Text(result.message).font(.system(size: 11, weight: .medium, design: .monospaced))
                if !result.diagnostic.isEmpty && result.diagnostic != result.message {
                    Text(result.diagnostic).font(.system(size: 10, design: .monospaced)).foregroundColor(.secondary)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                let c: Color = { switch result.tier {
                    case .direct: return .green; case .vfs: return .blue
                    case .remoteCall: return .orange; case .failed: return .red
                }}()
                Text(result.tier.rawValue).font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundColor(c)
                if let proc = result.process { Text(proc).font(.system(size: 10, design: .monospaced)).foregroundColor(.secondary) }
                Text(String(format: "%.0fms", result.duration * 1000)).font(.system(size: 10, design: .monospaced)).foregroundColor(.secondary)
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(Color(.secondarySystemBackground))
    }

    @ViewBuilder
    private func contentView(data: Data) -> some View {
        switch effectiveMode(for: data) {
        case .plist:
            if let pl = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
               let xd = try? PropertyListSerialization.data(fromPropertyList: pl, format: .xml, options: 0),
               let xs = String(data: xd, encoding: .utf8) {
                Text(xs).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            } else { fallbackText(data: data) }
        case .text: fallbackText(data: data)
        case .hex:
            Text(hexDump(data: data)).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
        case .auto: EmptyView()
        }
    }

    @ViewBuilder
    private func fallbackText(data: Data) -> some View {
        if let str = String(data: data, encoding: .utf8) {
            Text(str).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
        } else {
            Text(hexDump(data: data)).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func effectiveMode(for data: Data) -> PreviewMode {
        if viewMode != .auto { return viewMode }
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

// MARK: - File picker wrapper (unchanged)

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
            parent.data     = try? Data(contentsOf: url)
            parent.filename = url.lastPathComponent
        }
    }
}
