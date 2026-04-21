//
//  JetsamView.swift
//  lara
//
//  Jetsam memory manager.
//  Uses memorystatus_control directly (post-sbx-escape) to raise process
//  priority bands and set memory limits, preventing OOM kills.
//
//  Priority band reference:
//    0   idle / background         (killed first under pressure)
//    4   background suspended
//    5   audio background
//    8   mail / daemon
//   10   foreground app            (default)
//   12   active assertion
//   15   SpringBoard
//   16   critical daemon           (highest safe value)
//   17+  kernel protected          — never touch
//

import SwiftUI
import Darwin

// Declare memorystatus_control so Swift can call it without modifying the bridging header
@_silgen_name("memorystatus_control")
private func memorystatus_control(
    _ command: UInt32,
    _ pid: Int32,
    _ flags: UInt32,
    _ buffer: UnsafeMutableRawPointer?,
    _ buffersize: Int
) -> Int32

private let MEMORYSTATUS_CMD_GET_PRIORITY_LIST:      UInt32 = 1
private let MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES: UInt32 = 7
private let MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK: UInt32 = 5

// MARK: - Data model

struct JetsamProcess: Identifiable {
    let id      = UUID()
    let pid:    UInt32
    let uid:    UInt32
    let name:   String
    var targetBand:  Int  = 12
    var limitMB:     Int  = -1      // -1 = unlimited
    var isProtected: Bool = false
    var origBand:    Int  = 10      // recorded before modification for restore
}

// MARK: - JetsamView

struct JetsamView: View {
    @ObservedObject private var mgr = laramgr.shared

    @State private var processes:   [JetsamProcess] = []
    @State private var loading = false
    @State private var searchText  = ""
    @State private var status:      String?

    // Editor sheet
    @State private var editingIdx:  Int?
    @State private var showEditor   = false

    // Confirm restore-all
    @State private var showRestoreAll = false

    private var protectedProcesses: [JetsamProcess] {
        processes.filter { $0.isProtected }
    }

    private var filteredProcesses: [JetsamProcess] {
        let base = processes.filter { !$0.isProtected }
        guard !searchText.isEmpty else { return base }
        return base.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }

    // MARK: - Body

    var body: some View {
        List {
            // Protected section
            if !protectedProcesses.isEmpty {
                protectedSection
            }

            // All running processes
            runningSection
        }
        .listStyle(.insetGrouped)
        .searchable(text: $searchText, prompt: "Filter processes")
        .navigationTitle("Jetsam")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if !protectedProcesses.isEmpty {
                    Button("Restore All") { showRestoreAll = true }
                        .foregroundColor(.orange)
                }
                Button {
                    refresh()
                } label: {
                    if loading { ProgressView().scaleEffect(0.8) }
                    else { Image(systemName: "arrow.clockwise") }
                }
            }
        }
        .alert("Status", isPresented: .constant(status != nil)) {
            Button("OK") { status = nil }
        } message: { Text(status ?? "") }
        .alert("Restore all Jetsam changes?", isPresented: $showRestoreAll) {
            Button("Restore", role: .destructive) { restoreAll() }
            Button("Cancel", role: .cancel) {}
        }
        .sheet(isPresented: $showEditor) {
            if let idx = editingIdx {
                EditorSheet(process: $processes[idx], onApply: { apply(idx: idx) })
            }
        }
        .onAppear { refresh() }
    }

    // MARK: - Protected section

    private var protectedSection: some View {
        Section {
            ForEach(protectedProcesses) { proc in
                HStack(spacing: 10) {
                    Circle().fill(Color.green).frame(width: 8, height: 8)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(proc.name)
                            .font(.system(.body, design: .monospaced))
                            .fontWeight(.semibold)
                        HStack(spacing: 6) {
                            Text("band \(proc.origBand) → \(proc.targetBand)")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.secondary)
                            if proc.limitMB == -1 {
                                bandTag("unlimited", .blue)
                            } else {
                                bandTag("\(proc.limitMB) MB cap", .orange)
                            }
                        }
                    }
                    Spacer()
                    Text("pid \(proc.pid)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                    Button("Restore") {
                        restore(pid: proc.pid)
                    }
                    .font(.system(size: 12))
                    .buttonStyle(.bordered)
                    .tint(.orange)
                }
                .padding(.vertical, 2)
            }
        } header: {
            Text("Protected (\(protectedProcesses.count))")
        } footer: {
            Text("Restore before rebooting to avoid unexpected behaviour.")
                .foregroundColor(.orange)
        }
    }

    // MARK: - Running processes section

    private var runningSection: some View {
        Section {
            if loading {
                HStack { Spacer(); ProgressView(); Text("Scanning…").foregroundColor(.secondary); Spacer() }
            } else if filteredProcesses.isEmpty {
                Text(searchText.isEmpty ? "No processes found" : "No matches")
                    .foregroundColor(.secondary)
            } else {
                ForEach(filteredProcesses.indices, id: \.self) { i in
                    let proc = filteredProcesses[i]
                    processRow(proc)
                }
            }
        } header: {
            HStack {
                Text("Running (\(processes.count))")
                Spacer()
                Text("R = root  M = mobile")
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.secondary)
            }
        } footer: {
            Text("Tap a process to set its Jetsam priority band and memory limit. Safe range: 0–16.")
        }
    }

    @ViewBuilder
    private func processRow(_ proc: JetsamProcess) -> some View {
        HStack(spacing: 10) {
            Text(proc.uid == 0 ? "R" : "M")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(proc.uid == 0 ? .orange : .secondary)
                .frame(width: 14)

            VStack(alignment: .leading, spacing: 1) {
                Text(proc.name)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                Text("pid \(proc.pid)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary)
            }

            Spacer()

            Image(systemName: "shield")
                .foregroundColor(.secondary)
        }
        .contentShape(Rectangle())
        .onTapGesture {
            // Find index in the full processes array
            if let idx = processes.firstIndex(where: { $0.pid == proc.pid }) {
                editingIdx = idx
                showEditor = true
            }
        }
        .disabled(!mgr.dsready && !mgr.sbxready)
    }

    // MARK: - Editor sheet

    struct EditorSheet: View {
        @Binding var process: JetsamProcess
        let onApply: () -> Void
        @Environment(\.dismiss) private var dismiss

        @State private var bandDouble:  Double = 12
        @State private var limitDouble: Double = -1

        private let bandMarkers: [(Int, String)] = [
            (0,  "idle"), (4, "bg suspend"), (5, "bg audio"),
            (8,  "daemon"), (10, "foreground"), (12, "assertion"),
            (15, "SpringBoard"), (16, "critical — max safe")
        ]

        var body: some View {
            NavigationView {
                List {
                    // Info
                    Section("Process") {
                        LabeledContent("Name", value: process.name)
                        LabeledContent("PID",  value: "\(process.pid)")
                        LabeledContent("UID",  value: "\(process.uid) (\(process.uid == 0 ? "root" : "mobile"))")
                    }

                    // Priority band
                    Section {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                Text("Band")
                                    .font(.system(.body, design: .monospaced))
                                Spacer()
                                Text("\(Int(bandDouble))  · \(bandLabel(Int(bandDouble)))")
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundColor(bandColour(Int(bandDouble)))
                                    .fontWeight(.semibold)
                            }
                            Slider(value: $bandDouble, in: 0...16, step: 1)
                                .tint(bandColour(Int(bandDouble)))
                            // Quick markers
                            ScrollView(.horizontal, showsIndicators: false) {
                                HStack(spacing: 6) {
                                    ForEach(bandMarkers, id: \.0) { band, label in
                                        Button("\(band)") {
                                            bandDouble = Double(band)
                                        }
                                        .font(.system(size: 10, design: .monospaced))
                                        .buttonStyle(.bordered)
                                        .tint(Int(bandDouble) == band ? bandColour(band) : .secondary)
                                        .controlSize(.mini)
                                    }
                                }
                            }
                        }
                    } header: { Text("Priority Band") }
                    footer: { Text("Current foreground apps sit at band 10. SpringBoard is 15. Do not exceed 16.") }

                    // Memory limit
                    Section {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                Text("Memory Limit")
                                    .font(.system(.body, design: .monospaced))
                                Spacer()
                                Text(limitDouble < 0 ? "Unlimited" : "\(Int(limitDouble)) MB")
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundColor(limitDouble < 0 ? .blue : .orange)
                                    .fontWeight(.semibold)
                            }
                            Slider(value: $limitDouble, in: -1...2048, step: 1)
                                .tint(limitDouble < 0 ? .blue : .orange)
                            Toggle("Unlimited (no cap)", isOn: Binding(
                                get: { limitDouble < 0 },
                                set: { limitDouble = $0 ? -1 : 512 }
                            ))
                        }
                    } header: { Text("Memory Limit") }
                    footer: { Text("Unlimited removes the per-process footprint cap. A specific limit hard-caps a runaway process.") }

                    // Apply
                    Section {
                        Button {
                            process.targetBand = Int(bandDouble)
                            process.limitMB    = Int(limitDouble)
                            onApply()
                            dismiss()
                        } label: {
                            HStack {
                                Spacer()
                                Label("Apply Jetsam Policy", systemImage: "shield.lefthalf.filled")
                                    .fontWeight(.semibold)
                                Spacer()
                            }
                        }
                        .foregroundColor(.white)
                        .listRowBackground(Color.orange)
                    }
                }
                .listStyle(.insetGrouped)
                .navigationTitle(process.name)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }
                    }
                }
                .onAppear {
                    bandDouble  = Double(process.targetBand)
                    limitDouble = Double(process.limitMB)
                }
            }
        }

        private func bandLabel(_ b: Int) -> String {
            bandMarkers.last(where: { $0.0 <= b })?.1 ?? "?"
        }

        private func bandColour(_ b: Int) -> Color {
            switch b {
            case 0...4:   return .red
            case 5...9:   return .orange
            case 10...12: return .green
            case 13...15: return .blue
            default:      return .purple
            }
        }
    }

    // MARK: - Actions

    private func refresh() {
        guard !loading else { return }
        loading = true
        DispatchQueue.global(qos: .userInitiated).async {
            var result: [JetsamProcess] = []
            var count: Int32 = 0
            if let ptr = proclist(nil, &count), count > 0 {
                for i in 0..<Int(count) {
                    let e = ptr[i]
                    guard e.pid > 1 else { continue }
                    let name = withUnsafeBytes(of: e.name) { raw -> String in
                        let b = raw.bindMemory(to: UInt8.self)
                        let end = b.firstIndex(of: 0) ?? b.endIndex
                        return String(bytes: b[..<end], encoding: .utf8) ?? "?"
                    }
                    guard !name.isEmpty else { continue }
                    // Check if we already have a protected entry for this pid
                    let existing = self.processes.first(where: { $0.pid == e.pid })
                    var p = JetsamProcess(pid: e.pid, uid: e.uid, name: name)
                    if let ex = existing, ex.isProtected {
                        p.isProtected = true
                        p.targetBand  = ex.targetBand
                        p.limitMB     = ex.limitMB
                        p.origBand    = ex.origBand
                    }
                    result.append(p)
                }
                free_proclist(ptr)
            }
            DispatchQueue.main.async {
                // Merge: keep protected state from existing list for pids that disappeared
                self.processes = result.sorted { $0.name.lowercased() < $1.name.lowercased() }
                self.loading   = false
            }
        }
    }

    private func apply(idx: Int) {
        let proc = processes[idx]
        let band    = Int32(proc.targetBand)
        let limitMB = Int32(proc.limitMB)

        var ok = setJetsamBand(pid: proc.pid, band: band)

        if limitMB == -1 {
            // Unlimited: use a very large value for the high-water-mark command
            _ = memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK,
                                     proc.pid, UInt32(bitPattern: Int32.max), nil, 0)
        } else if limitMB > 0 {
            _ = memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK,
                                     proc.pid, UInt32(bitPattern: limitMB), nil, 0)
        }

        processes[idx].isProtected = ok
        processes[idx].origBand    = ok ? 10 : proc.origBand  // conservative default
        status = ok
            ? "Protected \(proc.name) (pid \(proc.pid)) → band \(band)\(limitMB == -1 ? ", unlimited" : limitMB > 0 ? ", \(limitMB)MB" : "")"
            : "memorystatus_control failed for \(proc.name) — sbx escape may be required"
    }

    private func restore(pid: Int32) {
        guard let idx = processes.firstIndex(where: { $0.pid == pid }) else { return }
        let proc = processes[idx]
        _ = setJetsamBand(pid: pid, band: Int32(proc.origBand))
        processes[idx].isProtected = false
        status = "Restored \(proc.name)"
    }

    private func restoreAll() {
        for proc in protectedProcesses {
            _ = setJetsamBand(pid: proc.pid, band: Int32(proc.origBand))
            if let idx = processes.firstIndex(where: { $0.pid == proc.pid }) {
                processes[idx].isProtected = false
            }
        }
        status = "All Jetsam changes restored"
    }

    // MARK: - memorystatus_control wrapper

    /// Sets a process's Jetsam priority band.
    /// Tries direct syscall first (works post-sbx-escape on some configs),
    /// then falls through silently — RC-based fallback can be added here later.
    private func setJetsamBand(pid: Int32, band: Int32) -> Bool {
        // memorystatus_priority_properties_t layout:
        //   int32_t  priority   (offset 0, size 4)
        //   uint64_t user_data  (offset 8, size 8, natural alignment)
        // Total: 16 bytes
        var buf = [UInt8](repeating: 0, count: 16)
        withUnsafeBytes(of: band) { src in
            buf.replaceSubrange(0..<4, with: src)
        }
        let ret = buf.withUnsafeMutableBytes { ptr in
            memorystatus_control(
                MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES,
                pid,
                0,
                ptr.baseAddress,
                16
            )
        }
        return ret == 0
    }

    // MARK: - Band label helpers (used by row display)

    private func bandColour(_ b: Int) -> Color {
        switch b {
        case 0...4:   return .red
        case 5...9:   return .orange
        case 10...12: return .green
        case 13...15: return .blue
        default:      return .purple
        }
    }

    @ViewBuilder
    private func bandTag(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .semibold, design: .monospaced))
            .foregroundColor(color)
            .padding(.horizontal, 4).padding(.vertical, 2)
            .background(
                RoundedRectangle(cornerRadius: 3)
                    .fill(color.opacity(0.12))
                    .overlay(RoundedRectangle(cornerRadius: 3).stroke(color.opacity(0.3), lineWidth: 0.5))
            )
    }
}
