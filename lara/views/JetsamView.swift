//
//  JetsamView.swift
//  lara
//
//  Jetsam memory manager.
//
//  Two independent actions per process:
//
//  Memory Limit (Direct Ledger Write)
//    Writes directly to ledger→entries[phys_footprint].le_limit via kwrite64.
//    Bypasses the memorystatus_control entitlement cap entirely.
//    Requires: exploit (KRW) + one-time scanner run.
//    No RC. No memorystatus entitlements.
//
//  Priority Band
//    Sets the jetsam kill-order band via memorystatus_control cmd7.
//    Tries direct call from lara first; falls back to RC (configd) if that fails.
//    Requires: exploit. RC recommended for cross-process reliability.
//
//  Priority band reference:
//    0   idle / background         (killed first)
//    4   background suspended
//    5   audio background
//    8   mail / daemon
//   10   foreground app            (default)
//   12   active assertion
//   15   SpringBoard
//   16   critical daemon           (highest safe value)
//

import SwiftUI
import Darwin

// MARK: - memorystatus_control

@_silgen_name("memorystatus_control")
func memorystatus_control(
    _ command:    Int32,
    _ pid:        Int32,
    _ flags:      UInt32,
    _ buffer:     UnsafeMutableRawPointer?,
    _ buffersize: Int
) -> Int32

let MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES: Int32 = 7
let MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES: Int32 = 8
let SYS_MEMORYSTATUS_CONTROL: UInt64 = 396   // iOS 17.x / xnu-10002.81.5

// MARK: - ScannerPhase

enum ScannerPhase: Equatable {
    case idle
    case running
    case ready
    case failed(String)

    var label: String {
        switch self {
        case .idle:           return "Not scanned"
        case .running:        return "Scanning…"
        case .ready:          return "Ready"
        case .failed(let r):  return "Failed: \(r)"
        }
    }

    var color: Color {
        switch self {
        case .idle:    return .secondary
        case .running: return .orange
        case .ready:   return .green
        case .failed:  return .red
        }
    }

    var isReady: Bool {
        if case .ready = self { return true }
        return LedgerScanner.cached != nil
    }

    var isRunning: Bool {
        if case .running = self { return true }
        return false
    }
}

// MARK: - JetsamProcess

struct JetsamProcess: Identifiable {
    let id   = UUID()
    let pid:  UInt32
    let uid:  UInt32
    let name: String

    var origBand:    Int  = 10
    var targetBand:  Int  = 10
    var bandApplied: Bool = false

    var ledgerLimitMB: Int? = nil  // nil = not yet written via KRW

    var isModified: Bool { bandApplied || ledgerLimitMB != nil }
}

// MARK: - JetsamView

struct JetsamView: View {

    @ObservedObject private var mgr = laramgr.shared

    @State private var processes:      [JetsamProcess] = []
    @State private var loading         = false
    @State private var searchText      = ""
    @State private var editingProcess: JetsamProcess?
    @State private var toast           = ""
    @State private var showToast       = false
    @State private var scannerPhase    = ScannerPhase.idle
    @State private var scannerLog      = ""

    // MARK: Derived

    private var modifiedProcesses: [JetsamProcess] {
        processes.filter(\.isModified)
    }

    private var unmodifiedProcesses: [JetsamProcess] {
        let base = processes.filter { !$0.isModified }
        guard !searchText.isEmpty else { return base }
        return base.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }

    private var rcAvailable: Bool {
        RemoteFileIO.shared.pool.values.contains { $0.state.isReady }
    }

    // MARK: Body

    var body: some View {
        List {
            scannerSection
            if !modifiedProcesses.isEmpty { modifiedSection }
            processListSection
        }
        .listStyle(.insetGrouped)
        .searchable(text: $searchText, prompt: "Filter processes")
        .navigationTitle("Jetsam Manager")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { refresh() } label: {
                    if loading { ProgressView().scaleEffect(0.8) }
                    else       { Image(systemName: "arrow.clockwise") }
                }
                .disabled(loading)
            }
        }
        .alert("Result", isPresented: $showToast) {
            Button("OK") { showToast = false }
        } message: {
            Text(toast)
        }
        .sheet(item: $editingProcess) { proc in
            EditorSheet(
                process:      proc,
                scannerPhase: scannerPhase,
                onLimitApplied: { limitMB in
                    updateProcess(pid: proc.pid) { $0.ledgerLimitMB = limitMB }
                },
                onBandApplied: { band in
                    updateProcess(pid: proc.pid) {
                        if !proc.bandApplied { $0.origBand = proc.origBand }
                        $0.targetBand  = band
                        $0.bandApplied = true
                    }
                },
                onResult: { msg in
                    toast     = msg
                    showToast = true
                }
            )
        }
        .onAppear {
            refresh()
            if LedgerScanner.cached != nil, case .idle = scannerPhase {
                scannerPhase = .ready
            }
        }
    }

    // MARK: Scanner section

    @ViewBuilder
    private var scannerSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {

                HStack(spacing: 8) {
                    Image(systemName: "memorychip")
                        .foregroundColor(.purple)
                    Text("Physical Footprint Scanner")
                        .font(.system(.body, design: .monospaced, weight: .semibold))
                    Spacer()
                    statusPill(scannerPhase.label, scannerPhase.color)
                }

                Text(
                    "Locates the kernel ledger entry for physical footprint in lara's own " +
                    "task struct. Once found, memory limits can be written directly, " +
                    "bypassing the ~2.2 GB cap that memorystatus_control cannot exceed."
                )
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.secondary)

                if case .failed(let reason) = scannerPhase {
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red).font(.caption)
                        Text(reason)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.red)
                    }
                }

                HStack(spacing: 8) {
                    VStack(alignment: .leading, spacing: 3) {
                        // Only hard requirement is KRW.
                        if !mgr.dsready {
                            reqRow("KRW not ready — run exploit first")
                        }
                    }
                    Spacer()
                    if scannerPhase.isRunning {
                        ProgressView().scaleEffect(0.9)
                    } else {
                        Button {
                            runScanner()
                        } label: {
                            Label(
                                scannerPhase.isReady ? "Re-scan" : "Scan",
                                systemImage: "magnifyingglass"
                            )
                            .font(.system(size: 13, weight: .semibold, design: .monospaced))
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.purple)
                        // RC no longer required — KRW (dsready) is the only gate.
                        .disabled(!mgr.dsready || scannerPhase.isRunning)
                    }
                }

                if scannerPhase.isReady, let offsets = LedgerScanner.cached {
                    Text(offsets.description)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundColor(.purple.opacity(0.8))
                        .padding(6)
                        .background(
                            RoundedRectangle(cornerRadius: 5)
                                .fill(Color.purple.opacity(0.06))
                                .overlay(RoundedRectangle(cornerRadius: 5)
                                    .stroke(Color.purple.opacity(0.2), lineWidth: 0.5))
                        )
                }
            }
            .padding(.vertical, 4)
        } header: {
            Text("Memory Scanner")
        } footer: {
            Text(
                "Runs once per session. No RC required — uses KRW only. " +
                "All memory limit writes after this need only KRW."
            )
        }
    }

    // MARK: Modified section

    @ViewBuilder
    private var modifiedSection: some View {
        Section {
            ForEach(modifiedProcesses) { proc in
                HStack(spacing: 10) {
                    Circle()
                        .fill(proc.ledgerLimitMB != nil ? Color.purple : Color.green)
                        .frame(width: 7, height: 7)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(proc.name)
                            .font(.system(.body, design: .monospaced, weight: .semibold))
                            .lineLimit(1)
                        HStack(spacing: 5) {
                            if let lim = proc.ledgerLimitMB {
                                inlineTag("\(lim) MB ledger", .purple)
                            }
                            if proc.bandApplied {
                                inlineTag("band \(proc.origBand)→\(proc.targetBand)", .green)
                            }
                        }
                    }
                    Spacer()
                    Text("pid \(proc.pid)")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                    Button {
                        restoreProcess(pid: proc.pid)
                    } label: {
                        Text("Restore")
                            .font(.system(size: 11, design: .monospaced))
                    }
                    .buttonStyle(.bordered)
                    .tint(.orange)
                    .controlSize(.small)
                }
                .padding(.vertical, 2)
                .contentShape(Rectangle())
                .onTapGesture { editingProcess = proc }
            }
        } header: {
            Text("Modified (\(modifiedProcesses.count))")
        } footer: {
            Text("Tap to re-edit. KRW ledger writes persist until reboot.")
                .foregroundColor(.orange)
        }
    }

    // MARK: Process list section

    @ViewBuilder
    private var processListSection: some View {
        Section {
            if loading {
                HStack {
                    Spacer()
                    ProgressView()
                    Text(" Scanning…")
                        .foregroundColor(.secondary)
                        .font(.system(.body, design: .monospaced))
                    Spacer()
                }
            } else if unmodifiedProcesses.isEmpty {
                Text(searchText.isEmpty ? "No processes found" : "No matches")
                    .foregroundColor(.secondary)
                    .font(.system(.body, design: .monospaced))
            } else {
                ForEach(unmodifiedProcesses) { proc in
                    processRow(proc)
                }
            }
        } header: {
            HStack {
                Text(searchText.isEmpty
                     ? "Running (\(processes.count))"
                     : "Results (\(unmodifiedProcesses.count) of \(processes.count))")
                Spacer()
                Text("R=root  M=mobile")
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.secondary)
            }
        } footer: {
            Text("Tap any process to configure its memory limit or priority band.")
        }
    }

    @ViewBuilder
    private func processRow(_ proc: JetsamProcess) -> some View {
        HStack(spacing: 10) {
            Text(proc.uid == 0 ? "R" : "M")
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .foregroundColor(proc.uid == 0 ? .orange : .secondary)
                .frame(width: 14)
            VStack(alignment: .leading, spacing: 1) {
                Text(proc.name)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                Text("pid \(proc.pid)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.system(size: 10))
                .foregroundColor(Color(.systemGray4))
        }
        .contentShape(Rectangle())
        .onTapGesture { editingProcess = proc }
    }

    // MARK: Actions

    /// Runs the ledger scanner on a background thread.
    /// No RC capture needed — scanner is pure KRW.
    private func runScanner() {
        guard !scannerPhase.isRunning else { return }
        guard mgr.dsready else {
            scannerPhase = .failed("KRW not ready — run exploit first")
            return
        }

        scannerPhase = .running
        scannerLog   = ""

        DispatchQueue.global(qos: .userInitiated).async {
            let result = LedgerScanner.runScanner()
            DispatchQueue.main.async {
                self.scannerLog   = result.log
                self.scannerPhase = result.ok ? .ready : .failed(result.detail)
            }
        }
    }

    private func refresh() {
        guard !loading else { return }
        loading = true

        DispatchQueue.global(qos: .userInitiated).async {
            var count: Int32 = 0
            guard let ptr = proclist(nil, &count), count > 0 else {
                DispatchQueue.main.async { self.loading = false }
                return
            }
            defer { free_proclist(ptr) }

            var result: [JetsamProcess] = []
            for i in 0..<Int(count) {
                let e = ptr[i]
                guard e.pid > 0 else { continue }
                let name = withUnsafeBytes(of: e.name) { raw in
                    String(bytes: raw.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "?"
                }
                result.append(JetsamProcess(pid: e.pid, uid: e.uid, name: name))
            }
            result.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }

            DispatchQueue.main.async {
                // Preserve modifications across refresh
                let prev = Dictionary(uniqueKeysWithValues: self.processes.map { ($0.pid, $0) })
                self.processes = result.map { p in
                    guard var existing = prev[p.pid] else { return p }
                    existing = p   // refresh pid/uid/name
                    return existing
                }
                self.loading = false
            }
        }
    }

    private func updateProcess(pid: UInt32, update: (inout JetsamProcess) -> Void) {
        guard let idx = processes.firstIndex(where: { $0.pid == pid }) else { return }
        update(&processes[idx])
        if editingProcess?.pid == pid { editingProcess = processes[idx] }
    }

    private func restoreProcess(pid: UInt32) {
        guard let proc = processes.first(where: { $0.pid == pid }) else { return }
        DispatchQueue.global(qos: .userInitiated).async {
            if proc.bandApplied {
                var buf = [UInt8](repeating: 0, count: 16)
                let b   = Int32(proc.origBand)
                withUnsafeBytes(of: b) { src in buf.replaceSubrange(0..<4, with: src) }
                _ = buf.withUnsafeMutableBytes { ptr in
                    memorystatus_control(
                        MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES,
                        Int32(pid), 0, ptr.baseAddress, 16
                    )
                }
            }
            DispatchQueue.main.async {
                self.updateProcess(pid: pid) { $0.bandApplied = false; $0.ledgerLimitMB = nil }
                self.toast = "Restored \(proc.name)" +
                    (proc.ledgerLimitMB != nil ? " (ledger write persists until reboot)" : "")
                self.showToast = true
            }
        }
    }

    // MARK: View helpers

    @ViewBuilder
    private func statusPill(_ text: String, _ color: Color) -> some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text(text)
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundColor(color)
        }
    }

    @ViewBuilder
    private func reqRow(_ text: String) -> some View {
        HStack(spacing: 5) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 10)).foregroundColor(.orange)
            Text(text)
                .font(.system(size: 10, design: .monospaced)).foregroundColor(.orange)
        }
    }

    @ViewBuilder
    private func inlineTag(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .semibold, design: .monospaced))
            .foregroundColor(color)
            .padding(.horizontal, 5).padding(.vertical, 2)
            .background(
                RoundedRectangle(cornerRadius: 3)
                    .fill(color.opacity(0.1))
                    .overlay(RoundedRectangle(cornerRadius: 3)
                        .stroke(color.opacity(0.3), lineWidth: 0.5))
            )
    }
}

// MARK: - EditorSheet

private struct EditorSheet: View {

    let process:        JetsamProcess
    let scannerPhase:   ScannerPhase
    let onLimitApplied: (Int)    -> Void
    let onBandApplied:  (Int)    -> Void
    let onResult:       (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var mgr = laramgr.shared

    @State private var targetMB:      Double = 2048
    @State private var limitBusy      = false
    @State private var limitFeedback  = ""

    @State private var bandDouble:    Double = 10
    @State private var bandBusy       = false
    @State private var bandFeedback   = ""

    private let bandMarkers: [(v: Int, l: String)] = [
        (0,  "idle"),        (4,  "bg-suspend"), (5,  "bg-audio"),
        (8,  "daemon"),      (10, "foreground"),  (12, "assertion"),
        (15, "SpringBoard"), (16, "critical")
    ]

    private var scannerReady: Bool { scannerPhase.isReady }

    var body: some View {
        NavigationView {
            List {
                infoSection
                memoryLimitSection
                priorityBandSection
            }
            .listStyle(.insetGrouped)
            .navigationTitle(process.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear {
                bandDouble = Double(process.targetBand)
                if let lim = process.ledgerLimitMB { targetMB = Double(lim) }
            }
        }
    }

    // MARK: Info

    private var infoSection: some View {
        Section("Process") {
            row("Name",  process.name)
            row("PID",   "\(process.pid)")
            row("UID",   "\(process.uid) (\(process.uid == 0 ? "root" : "mobile"))")
            if let lim = process.ledgerLimitMB {
                LabeledContent("Active Limit") {
                    Text("\(lim) MB  (KRW)")
                        .foregroundColor(.purple)
                        .font(.system(.body, design: .monospaced))
                }
            }
            if process.bandApplied {
                LabeledContent("Band") {
                    Text("\(process.origBand) → \(process.targetBand)")
                        .foregroundColor(.green)
                        .font(.system(.body, design: .monospaced))
                }
            }
        }
    }

    // MARK: Memory limit section
    //
    // Writes directly to ledger→entries[phys_footprint].le_limit.
    // Independent of Priority Band — the two sections do entirely different things.

    @ViewBuilder
    private var memoryLimitSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {

                HStack {
                    Image(systemName: "memorychip").foregroundColor(.purple)
                    Text("Direct Ledger Write")
                        .font(.system(.body, design: .monospaced, weight: .semibold))
                    Spacer()
                    Text(scannerReady ? "KRW only" : "scanner required")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(scannerReady ? Color.purple.opacity(0.7) : .orange)
                }

                HStack {
                    Text("Target").foregroundColor(.secondary)
                        .font(.system(.body, design: .monospaced))
                    Spacer()
                    Text("\(Int(targetMB)) MB  (\(String(format: "%.2f", targetMB/1024)) GB)")
                        .font(.system(.body, design: .monospaced, weight: .semibold))
                        .foregroundColor(scannerReady ? .purple : .secondary)
                }

                // Device-agnostic range: 256 MB – 6 GB. No entitlement-imposed ceiling.
                Slider(value: $targetMB, in: 256...6144, step: 64)
                    .tint(.purple).disabled(!scannerReady)

                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach([512, 1024, 1536, 2048, 3072, 4096, 5120, 6144], id: \.self) { mb in
                            Button("\(mb) MB") { targetMB = Double(mb) }
                                .font(.system(size: 10, weight: .medium, design: .monospaced))
                                .buttonStyle(.bordered)
                                .tint(Int(targetMB) == mb ? .purple : .secondary)
                                .controlSize(.mini)
                                .disabled(!scannerReady)
                        }
                    }
                }

                Button { applyLimit() } label: {
                    HStack {
                        Spacer()
                        if limitBusy {
                            ProgressView().scaleEffect(0.8).tint(.white)
                            Text(" Writing to ledger…")
                                .font(.system(.body, design: .monospaced)).foregroundColor(.white)
                        } else {
                            Image(systemName: "memorychip")
                            Text("Apply \(Int(targetMB)) MB Limit")
                                .font(.system(.body, design: .monospaced, weight: .semibold))
                        }
                        Spacer()
                    }
                    .foregroundColor(.white).padding(.vertical, 4)
                }
                .listRowBackground(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(scannerReady && mgr.dsready && !limitBusy
                              ? Color.purple : Color.gray)
                )
                .disabled(!scannerReady || !mgr.dsready || limitBusy)

                if !limitFeedback.isEmpty {
                    Text(limitFeedback)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(limitFeedback.hasPrefix("✓") ? .green : .red)
                }
            }
            .padding(.vertical, 4)
        } header: {
            Text("Memory Limit")
        } footer: {
            Text(scannerReady
                 ? "Writes task→ledger→entries[phys_footprint].le_limit directly. Reboot clears the change."
                 : "Run the Memory Scanner on the Jetsam Manager page first.")
                .foregroundColor(scannerReady ? .secondary : .orange)
        }
    }

    // MARK: Priority band section
    //
    // Sets kill-order under jetsam pressure. No memory cap effect.
    // Independent of the Memory Limit section above.

    @ViewBuilder
    private var priorityBandSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {

                HStack {
                    Image(systemName: "list.number").foregroundColor(.green)
                    Text("Jetsam Priority Band")
                        .font(.system(.body, design: .monospaced, weight: .semibold))
                    Spacer()
                    Text("Band \(Int(bandDouble))  · \(bandLabel(Int(bandDouble)))")
                        .font(.system(.body, design: .monospaced, weight: .semibold))
                        .foregroundColor(bandColor(Int(bandDouble)))
                }

                Slider(value: $bandDouble, in: 0...16, step: 1)
                    .tint(bandColor(Int(bandDouble)))

                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(bandMarkers, id: \.v) { m in
                            Button("\(m.v)") { bandDouble = Double(m.v) }
                                .font(.system(size: 10, weight: .medium, design: .monospaced))
                                .buttonStyle(.bordered)
                                .tint(Int(bandDouble) == m.v ? bandColor(m.v) : .secondary)
                                .controlSize(.mini)
                        }
                    }
                }

                Button { applyBand() } label: {
                    HStack {
                        Spacer()
                        if bandBusy {
                            ProgressView().scaleEffect(0.8).tint(.white)
                            Text(" Setting band…")
                                .font(.system(.body, design: .monospaced)).foregroundColor(.white)
                        } else {
                            Image(systemName: "list.number")
                            Text("Set Band \(Int(bandDouble))  (\(bandLabel(Int(bandDouble))))")
                                .font(.system(.body, design: .monospaced, weight: .semibold))
                        }
                        Spacer()
                    }
                    .foregroundColor(.white).padding(.vertical, 4)
                }
                .listRowBackground(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(!bandBusy ? Color.green.opacity(0.85) : Color.gray)
                )
                .disabled(bandBusy)

                if !bandFeedback.isEmpty {
                    Text(bandFeedback)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(bandFeedback.hasPrefix("✓") ? .green : .red)
                }
            }
            .padding(.vertical, 4)
        } header: {
            Text("Priority Band")
        } footer: {
            Text(
                "Controls kill ORDER under memory pressure. " +
                "Higher band = killed later. 10 = foreground default. " +
                "This does NOT set a memory hard cap — use Memory Limit above for that."
            )
        }
    }

    // MARK: applyLimit

    private func applyLimit() {
        guard !limitBusy else { return }
        limitBusy     = true
        limitFeedback = ""
        let pid = Int32(process.pid)
        let mb  = Int32(targetMB)

        DispatchQueue.global(qos: .userInitiated).async {
            let result = LedgerScanner.applyLimit(pid: pid, targetMB: mb)
            DispatchQueue.main.async {
                self.limitBusy = false
                if result.ok {
                    self.limitFeedback = "✓ \(result.detail)"
                    self.onLimitApplied(Int(mb))
                    self.onResult("Memory limit set on \(self.process.name): \(result.detail)")
                } else {
                    self.limitFeedback = "✗ \(result.detail)"
                    self.onResult("Memory limit failed (\(self.process.name)): \(result.detail)")
                }
            }
        }
    }

    // MARK: applyBand

    private func applyBand() {
        guard !bandBusy else { return }

        // RC pool must be read on the main thread before dispatching.
        var captures: [(rc: RemoteCall, trojan: UInt64, name: String)] = []
        let rcio = RemoteFileIO.shared
        for pName in ["configd", "SpringBoard", "securityd"] {
            guard case .ready = rcio.pool[pName]?.state,
                  let rc = rcio.pool[pName]?.rc else { continue }
            let t = rc.trojanMem
            guard t != 0 else { continue }
            captures.append((rc, t, pName))
        }

        bandBusy     = true
        bandFeedback = ""
        let pid  = Int32(process.pid)
        let band = Int32(bandDouble)

        DispatchQueue.global(qos: .userInitiated).async {
            var buf = [UInt8](repeating: 0, count: 16)
            withUnsafeBytes(of: band) { src in buf.replaceSubrange(0..<4, with: src) }

            // Attempt 1: direct call from lara (works when sandbox escape is active)
            var ok     = false
            var source = "direct"
            let ret = buf.withUnsafeMutableBytes { ptr in
                memorystatus_control(
                    MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES,
                    pid, 0, ptr.baseAddress, 16
                )
            }
            ok = ret == 0

            // Attempt 2: RC fallback via configd/SpringBoard/securityd (root, cmd7 allowed)
            if !ok {
                for cap in captures {
                    buf.withUnsafeBytes { bytes in
                        cap.rc.remote_write(cap.trojan,
                                            from: bytes.baseAddress,
                                            size: UInt64(16))
                    }
                    let rcRet = Int32(bitPattern: UInt32(
                        rcio.callIn(rc: cap.rc, name: "syscall", args: [
                            SYS_MEMORYSTATUS_CONTROL,
                            UInt64(MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES),
                            UInt64(bitPattern: Int64(pid)),
                            0, cap.trojan, 16
                        ], timeout: 500) & 0xFFFF_FFFF
                    ))
                    if rcRet == 0 {
                        ok     = true
                        source = "rc:\(cap.name)"
                        break
                    }
                }
            }

            DispatchQueue.main.async {
                self.bandBusy = false
                if ok {
                    self.bandFeedback = "✓ band \(band) via \(source)"
                    self.onBandApplied(Int(band))
                    self.onResult(
                        "Band \(band) (\(self.bandLabel(Int(band)))) set on \(self.process.name)"
                    )
                } else {
                    self.bandFeedback  = "✗ failed (errno \(errno))"
                    self.bandFeedback += captures.isEmpty
                        ? " — initialise RC on configd for best reliability"
                        : " — RC also failed"
                    self.onResult("Band apply failed for \(self.process.name): errno \(errno)")
                }
            }
        }
    }

    // MARK: Helpers

    private func bandLabel(_ b: Int) -> String {
        bandMarkers.last(where: { $0.v <= b })?.l ?? "?"
    }

    private func bandColor(_ b: Int) -> Color {
        switch b {
        case 0...4:   return .red
        case 5...9:   return .orange
        case 10...12: return .green
        case 13...15: return .blue
        default:      return .purple
        }
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String) -> some View {
        LabeledContent(label) {
            Text(value).font(.system(.body, design: .monospaced))
        }
    }
}
