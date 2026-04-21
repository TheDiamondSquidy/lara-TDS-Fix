//
//  ProcessInspectorView.swift
//  lara — TDS fork
//
//  Browse all running processes. Each tile shows:
//    • Name, PID, R/M privilege tag
//    • Resident memory (via proc_pidinfo PROC_PIDTASKINFO; falls back to "—")
//    • RC pool status badge
//
//  Tapping a tile opens a detail sheet with full task info and actions:
//    • Terminate (SIGTERM / SIGKILL — works post-sbx-escape for mobile processes)
//    • Init RC / Destroy RC
//    • Browse file jurisdiction (opens RC file manager at process's likely path)
//
//  proc_pidinfo requires no special entitlement post-sbx-escape on jailbroken devices.
//  If it fails, memory fields show "—" gracefully.
//

import SwiftUI
import Darwin
import UniformTypeIdentifiers

// MARK: - proc_pidinfo binding

@_silgen_name("proc_pidinfo")
private func _proc_pidinfo(
    _ pid: Int32,
    _ flavor: Int32,
    _ arg: UInt64,
    _ buffer: UnsafeMutableRawPointer?,
    _ buffersize: Int32
) -> Int32

private let PROC_PIDTASKINFO_FLAVOR: Int32 = 4

/// Mirrors the layout of struct proc_taskinfo from <proc_info.h>.
/// Total size: 6 × UInt64 (48) + 12 × Int32 (48) = 96 bytes.
private struct ProcTaskInfo {
    var pti_virtual_size:       UInt64 = 0   // virtual memory (bytes)
    var pti_resident_size:      UInt64 = 0   // resident memory (bytes)
    var pti_total_user:         UInt64 = 0
    var pti_total_system:       UInt64 = 0
    var pti_threads_user:       UInt64 = 0
    var pti_threads_system:     UInt64 = 0
    var pti_policy:             Int32  = 0
    var pti_faults:             Int32  = 0
    var pti_pageins:            Int32  = 0
    var pti_cow_faults:         Int32  = 0
    var pti_messages_sent:      Int32  = 0
    var pti_messages_received:  Int32  = 0
    var pti_syscalls_mach:      Int32  = 0
    var pti_syscalls_unix:      Int32  = 0
    var pti_csw:                Int32  = 0
    var pti_threadnum:          Int32  = 0
    var pti_numrunning:         Int32  = 0
    var pti_priority:           Int32  = 0
}

private func getTaskInfo(pid: Int32) -> ProcTaskInfo? {
    var info = ProcTaskInfo()
    let ret  = withUnsafeMutableBytes(of: &info) { ptr in
        _proc_pidinfo(pid, PROC_PIDTASKINFO_FLAVOR, 0,
                      ptr.baseAddress, Int32(MemoryLayout<ProcTaskInfo>.size))
    }
    return ret > 0 ? info : nil
}

// MARK: - Enriched process model

struct InspectedProcess: Identifiable {
    let id  = UUID()
    let pid: UInt32
    let uid: UInt32
    let name: String

    // Populated lazily in detail sheet
    fileprivate var taskInfo: ProcTaskInfo? = nil

    var isRoot: Bool { uid == 0 }

    var privilegeLabel: String { isRoot ? "R" : "M" }

    var residentMB: String {
        guard let ti = taskInfo, ti.pti_resident_size > 0 else { return "—" }
        return String(format: "%.1f MB", Double(ti.pti_resident_size) / (1024 * 1024))
    }

    var virtualMB: String {
        guard let ti = taskInfo, ti.pti_virtual_size > 0 else { return "—" }
        return String(format: "%.1f MB", Double(ti.pti_virtual_size) / (1024 * 1024))
    }

    /// Best guessed file jurisdiction path based on name / uid.
    var suggestedPath: String {
        if isRoot { return "/private/var/db" }
        return "/private/var/mobile"
    }
}

// MARK: - ProcessInspectorView

struct ProcessInspectorView: View {
    @ObservedObject private var mgr  = laramgr.shared
    @ObservedObject private var rcio = RemoteFileIO.shared

    @State private var processes:  [InspectedProcess] = []
    @State private var loading     = false
    @State private var searchText  = ""
    @State private var selected:   InspectedProcess? = nil

    private var filtered: [InspectedProcess] {
        guard !searchText.isEmpty else { return processes }
        return processes.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }

    var body: some View {
        List {
            if loading {
                HStack {
                    Spacer()
                    ProgressView()
                    Text("Scanning…").foregroundColor(.secondary)
                    Spacer()
                }
            } else if filtered.isEmpty {
                Text(searchText.isEmpty ? "No processes found" : "No matches")
                    .foregroundColor(.secondary)
            } else {
                ForEach(filtered) { proc in
                    processRow(proc)
                        .contentShape(Rectangle())
                        .onTapGesture { selected = proc }
                }
            }
        }
        .listStyle(.insetGrouped)
        .searchable(text: $searchText, prompt: "Search processes")
        .navigationTitle("Process Inspector")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { refresh() } label: {
                    if loading { ProgressView().scaleEffect(0.8) }
                    else { Image(systemName: "arrow.clockwise") }
                }
            }
        }
        .sheet(item: $selected) { proc in
            ProcessDetailSheet(
                process: proc,
                rcPoolEntry: rcio.pool[proc.name],
                onInit: { initProcess(proc.name) },
                onDestroy: { rcio.destroyProc(proc.name) }
            )
        }
        .onAppear { refresh() }
    }

    // MARK: - Row

    @ViewBuilder
    private func processRow(_ proc: InspectedProcess) -> some View {
        HStack(spacing: 10) {
            // Privilege tag
            Text(proc.privilegeLabel)
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(proc.isRoot ? .orange : .blue)
                .frame(width: 14)

            // State dot
            Circle()
                .fill(poolDotColor(for: proc.name))
                .frame(width: 7, height: 7)

            // Name + pid
            VStack(alignment: .leading, spacing: 1) {
                Text(proc.name)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                HStack(spacing: 8) {
                    Text("pid \(proc.pid)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                    if let ti = proc.taskInfo {
                        Text(String(format: "%.1f MB", Double(ti.pti_resident_size) / (1024 * 1024)))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                }
            }

            Spacer()

            Image(systemName: "chevron.right")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 2)
    }

    // MARK: - Helpers

    private func poolDotColor(for name: String) -> Color {
        guard let entry = rcio.pool[name] else { return Color(.systemGray4) }
        switch entry.state {
        case .ready:                   return .green
        case .initializing, .spawning: return .blue
        case .failed:                  return .red
        case .uninitialized:           return Color(.systemGray4)
        }
    }

    private func refresh() {
        guard !loading else { return }
        loading = true
        DispatchQueue.global(qos: .userInitiated).async {
            let raw = rcio.listRunningProcesses()
            // Enrich with task info while on background queue
            let enriched: [InspectedProcess] = raw.map { rp in
                var p = InspectedProcess(pid: rp.pid, uid: rp.uid, name: rp.name)
                p.taskInfo = getTaskInfo(pid: Int32(rp.pid))
                return p
            }
            DispatchQueue.main.async {
                self.processes = enriched
                self.loading   = false
            }
        }
    }

    private func initProcess(_ name: String) {
        guard mgr.dsready else { return }
        DispatchQueue.global(qos: .userInitiated).async {
            rcio.addArbitraryProcess(name)
            _ = rcio.rcProc(for: name, spawnIfNeeded: false)
        }
    }
}

// MARK: - Process detail sheet

struct ProcessDetailSheet: View {
    let process:      InspectedProcess
    let rcPoolEntry:  RCPoolEntry?
    let onInit:       () -> Void
    let onDestroy:    () -> Void

    @ObservedObject private var mgr  = laramgr.shared
    @Environment(\.dismiss) private var dismiss

    @State private var killStatus: String?
    @State private var confirmKill: TerminateMode? = nil
    @State private var showNavigate = false

    enum TerminateMode: Identifiable {
        case sigterm, sigkill
        var id: Int { self == .sigterm ? 15 : 9 }
        var signal: Int32 { self == .sigterm ? SIGTERM : SIGKILL }
        var label: String { self == .sigterm ? "SIGTERM (graceful)" : "SIGKILL (force)" }
    }

    private var isRCReady: Bool { rcPoolEntry?.state.isReady == true }

    var body: some View {
        NavigationView {
            List {
                // Identity
                Section("Identity") {
                    infoRow("Name", process.name)
                    infoRow("PID",  "\(process.pid)")
                    infoRow("UID",  "\(process.uid) (\(process.isRoot ? "root" : "mobile"))")
                }

                // Memory
                Section("Memory") {
                    if let ti = process.taskInfo {
                        infoRow("Resident", String(format: "%.1f MB", Double(ti.pti_resident_size) / (1024 * 1024)))
                        infoRow("Virtual",  String(format: "%.1f MB", Double(ti.pti_virtual_size) / (1024 * 1024)))
                        infoRow("Threads",  "\(ti.pti_threadnum) (\(ti.pti_numrunning) running)")
                        infoRow("Faults",   "\(ti.pti_faults)")
                        infoRow("Priority", "\(ti.pti_priority)")
                    } else {
                        Text("Memory info unavailable — proc_pidinfo failed (may need exploit)")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                }

                // RC pool status
                Section("RemoteCall") {
                    if let entry = rcPoolEntry {
                        HStack {
                            Text("Status")
                            Spacer()
                            Text(entry.state.description)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundColor(rcStateColor(entry.state))
                        }
                    } else {
                        Text("Not in RC pool")
                            .foregroundColor(.secondary)
                            .font(.system(size: 12, design: .monospaced))
                    }

                    if isRCReady {
                        Button(role: .destructive) { onDestroy(); dismiss() } label: {
                            Label("Destroy RC Session", systemImage: "xmark.circle")
                        }
                        .foregroundColor(.red)
                    } else {
                        Button {
                            onInit()
                            dismiss()
                        } label: {
                            Label("Initialise RC", systemImage: "bolt")
                        }
                        .disabled(!mgr.dsready)
                    }
                }

                // File jurisdiction
                Section(header: Text("File Jurisdiction")) {
                    // Navigate button — pushes RC file manager at the suggested path
                    NavigationLink {
                        FileManagerViewAtPath(startPath: process.suggestedPath)
                    } label: {
                        Label("Browse \(process.suggestedPath)", systemImage: "folder.badge.gear")
                    }

                    Button {
                        UIPasteboard.general.string = process.suggestedPath
                        killStatus = "Copied path: \(process.suggestedPath)"
                    } label: {
                        Label("Copy Suggested Path", systemImage: "doc.on.doc")
                    }
                } footer: {
                    Text("Suggested path is estimated from process privilege. Use RC File Manager to navigate freely.")
                        .font(.caption)
                }

                // Terminate
                Section("Terminate") {
                    if let status = killStatus {
                        Text(status)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.secondary)
                    }

                    Button {
                        confirmKill = .sigterm
                    } label: {
                        Label("Send SIGTERM (graceful)", systemImage: "stop.circle")
                    }
                    .foregroundColor(.orange)

                    Button(role: .destructive) {
                        confirmKill = .sigkill
                    } label: {
                        Label("Send SIGKILL (force)", systemImage: "xmark.octagon.fill")
                    }
                } footer: {
                    Text("Killing root processes may require root or RC. Mobile processes can be killed post-sbx-escape.")
                        .font(.caption)
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle(process.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .alert("Terminate \(process.name)?",
                   isPresented: .constant(confirmKill != nil),
                   presenting: confirmKill) { mode in
                Button("Send \(mode.label)", role: .destructive) {
                    let sig  = mode.signal
                    let pid  = Int32(process.pid)
                    confirmKill = nil
                    let ret = Darwin.kill(pid, sig)
                    killStatus = ret == 0
                        ? "Sent \(mode.label) to pid \(pid)"
                        : "kill() returned \(ret) (errno=\(errno)) — may need root"
                }
                Button("Cancel", role: .cancel) { confirmKill = nil }
            } message: { mode in
                Text("This will send \(mode.label) to pid \(process.pid).")
            }
        }
    }

    @ViewBuilder
    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(value)
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.secondary)
                .textSelection(.enabled)
        }
    }

    private func rcStateColor(_ state: RCPoolEntry.State) -> Color {
        switch state {
        case .ready:                   return .green
        case .initializing, .spawning: return .blue
        case .failed:                  return .red
        case .uninitialized:           return .secondary
        }
    }
}

// MARK: - FileManagerView with configurable start path

/// Thin wrapper around FileManagerView that opens at a specified path.
/// This allows ProcessInspectorView (and others) to deep-link into the file manager.
struct FileManagerViewAtPath: View {
    let startPath: String

    @ObservedObject private var mgr  = laramgr.shared
    @ObservedObject private var rcio = RemoteFileIO.shared

    @State private var path: String
    @State private var entries: [(name: String, isDir: Bool, size: Int64)] = []
    @State private var listSource = ""
    @State private var loading    = false
    @State private var status: String?

    @State private var processOverride: String? = nil
    @State private var showProcessSelector = false
    @State private var showPicker   = false
    @State private var pickedData:  Data?
    @State private var pickedName:  String?
    @State private var previewPath:   String?
    @State private var previewResult: (data: Data?, result: RCIOResult)?
    @State private var showPreview  = false
    @State private var deleteTarget: String?
    @State private var showDeleteConfirm = false
    @State private var renameTarget: String?
    @State private var renameDest   = ""
    @State private var showRename   = false
    @State private var lastOpResult: RCIOResult?
    @State private var showDebug    = false

    init(startPath: String) {
        self.startPath = startPath
        _path = State(initialValue: startPath)
    }

    var body: some View {
        // Reuse FileManagerView's logic but pre-seeded with startPath.
        // We embed the full file manager content here to share the startPath state.
        VStack(spacing: 0) {
            breadcrumb
            Divider()
            fileList
        }
        .navigationTitle("Browse")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { showPicker = true } label: { Image(systemName: "plus") }
                    .disabled(!mgr.dsready)
            }
        }
        .alert("Status", isPresented: .constant(status != nil)) {
            Button("OK") { status = nil }
        } message: { Text(status ?? "") }
        .alert("Delete", isPresented: $showDeleteConfirm, presenting: deleteTarget) { t in
            Button("Delete", role: .destructive) { handleDelete(t) }
            Button("Cancel", role: .cancel) {}
        } message: { t in Text("Delete \(URL(fileURLWithPath: t).lastPathComponent)?") }
        .alert("Rename", isPresented: $showRename, presenting: renameTarget) { t in
            TextField("New name", text: $renameDest)
            Button("Rename") {
                let dest = (path == "/" ? "" : path) + "/" + renameDest
                handleMove(from: t, to: dest)
            }
            Button("Cancel", role: .cancel) {}
        } message: { t in Text("Rename \(URL(fileURLWithPath: t).lastPathComponent)") }
        .sheet(isPresented: $showPicker) {
            RCFilePickerLite(data: $pickedData, filename: $pickedName)
        }
        .sheet(isPresented: $showPreview) {
            if let p = previewPath, let r = previewResult {
                FilePreviewSheet(path: p, data: r.data, result: r.result)
            }
        }
        .onChange(of: pickedData) { data in
            guard let data else { return }
            pickedData = nil
            let name = pickedName ?? "lara_new_\(Int(Date().timeIntervalSince1970)).bin"
            let target = (path == "/" ? "" : path) + "/" + name
            pickedName = nil
            DispatchQueue.global(qos: .userInitiated).async {
                let r = rcio.write(path: target, data: data)
                DispatchQueue.main.async { status = r.message; if r.ok { loadEntries() } }
            }
        }
        .onAppear { loadEntries() }
    }

    private var breadcrumb: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 2) {
                Button("/") { navigate(to: "/") }
                    .font(.system(size: 12, design: .monospaced)).foregroundColor(.blue)
                ForEach(Array(path.components(separatedBy: "/").filter { !$0.isEmpty }.enumerated()), id: \.offset) { i, part in
                    Text(" / ").font(.system(size: 12, design: .monospaced)).foregroundColor(.secondary)
                    Button(part) {
                        let comps = path.components(separatedBy: "/").filter { !$0.isEmpty }
                        navigate(to: "/" + comps[0...i].joined(separator: "/"))
                    }
                    .font(.system(size: 12, design: .monospaced)).foregroundColor(.blue)
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 6)
        }
        .background(Color(.secondarySystemBackground))
    }

    private var fileList: some View {
        List {
            if loading {
                HStack { Spacer(); ProgressView(); Text("Loading…").foregroundColor(.secondary); Spacer() }
            } else if entries.isEmpty {
                Text("Empty or inaccessible").foregroundColor(.secondary)
                    .font(.system(.body, design: .monospaced))
            } else {
                if path != "/" {
                    Button {
                        let p = (path as NSString).deletingLastPathComponent
                        navigate(to: p.isEmpty ? "/" : p)
                    } label: {
                        HStack {
                            Image(systemName: "arrow.up.doc.fill").foregroundColor(.secondary).frame(width: 22)
                            Text("..").font(.system(.body, design: .monospaced))
                        }
                    }
                }
                ForEach(entries, id: \.name) { entry in
                    let full = (path == "/" ? "" : path) + "/" + entry.name
                    HStack(spacing: 10) {
                        Image(systemName: entry.isDir ? "folder.fill" : "doc")
                            .foregroundColor(entry.isDir ? .yellow : .secondary).frame(width: 22)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(entry.name).font(.system(.body, design: .monospaced)).lineLimit(1)
                            if !entry.isDir {
                                Text(entry.size.fileSizeString)
                                    .font(.system(size: 11, design: .monospaced)).foregroundColor(.secondary)
                            }
                        }
                        Spacer()
                        if !entry.isDir {
                            Button {
                                previewPath = full; previewResult = nil; showPreview = true
                                DispatchQueue.global(qos: .userInitiated).async {
                                    let (d, r) = rcio.read(path: full, maxSize: 256*1024)
                                    DispatchQueue.main.async { previewResult = (d, r); lastOpResult = r }
                                }
                            } label: { Image(systemName: "eye") }
                            .buttonStyle(.borderless).foregroundColor(.blue)
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { if entry.isDir { navigate(to: full) } }
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) { deleteTarget = full; showDeleteConfirm = true } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
            }
        }
        .listStyle(.plain)
        .refreshable { loadEntries() }
    }

    private func navigate(to newPath: String) {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        let canonical = (Darwin.realpath(newPath, &buf) != nil) ? String(cString: buf) : newPath
        path = canonical
        loadEntries()
    }

    private func loadEntries() {
        let tp = path; loading = true; entries = []; listSource = ""
        DispatchQueue.global(qos: .userInitiated).async {
            let (e, src) = rcio.listDir(path: tp)
            DispatchQueue.main.async {
                guard self.path == tp else { return }
                self.entries = e; self.listSource = src; self.loading = false
            }
        }
    }

    private func handleDelete(_ path: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let r = rcio.delete(path: path)
            DispatchQueue.main.async { status = r.message; if r.ok { loadEntries() } }
        }
    }

    private func handleMove(from src: String, to dst: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let r = rcio.move(from: src, to: dst)
            DispatchQueue.main.async { status = r.message; if r.ok { loadEntries() } }
        }
    }
}

// MARK: - Minimal file picker for browse-only context

private struct RCFilePickerLite: UIViewControllerRepresentable {
    @Binding var data: Data?
    @Binding var filename: String?
    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let p = UIDocumentPickerViewController(forOpeningContentTypes: [.data, .item], asCopy: true)
        p.delegate = context.coordinator; return p
    }
    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let parent: RCFilePickerLite
        init(_ p: RCFilePickerLite) { parent = p }
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard let url = urls.first else { return }
            _ = url.startAccessingSecurityScopedResource()
            defer { url.stopAccessingSecurityScopedResource() }
            parent.data = try? Data(contentsOf: url)
            parent.filename = url.lastPathComponent
        }
    }
}
