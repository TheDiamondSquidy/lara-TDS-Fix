//
//  ProcessSelectorView.swift
//  lara
//
//  Two-section process picker.
//  Section 1 — Recommended: curated pool with status tags and init/spawn controls.
//  Section 2 — All Running: live list from proclist() with tags showing pool state.
//

import SwiftUI

struct ProcessSelectorView: View {
    @ObservedObject private var rcio = RemoteFileIO.shared
    @ObservedObject private var mgr  = laramgr.shared

    /// Optional path context — used to badge the default-routed process.
    let pathContext: String?

    /// When non-nil, the user is picking an override for the next operation.
    /// Set to the selected process name and dismiss, or nil to clear override.
    @Binding var selectedOverride: String?

    @Environment(\.dismiss) private var dismiss

    @State private var runningProcs: [RunningProcess] = []
    @State private var loadingProcs  = false
    @State private var searchText    = ""
    @State private var confirmSpawn: String?

    private var routedProcess: String? {
        pathContext.map { rcio.rcBestProcess(for: $0) }
    }

    // MARK: - Body

    var body: some View {
        NavigationView {
            List {
                recommendedSection
                runningSection
            }
            .listStyle(.insetGrouped)
            .searchable(text: $searchText, prompt: "Filter processes")
            .navigationTitle("Processes")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { refreshRunning() } label: {
                        if loadingProcs { ProgressView().scaleEffect(0.7) }
                        else { Image(systemName: "arrow.clockwise") }
                    }
                }
            }
            .alert("Spawn \(confirmSpawn ?? "")?", isPresented: .constant(confirmSpawn != nil)) {
                Button("Spawn via kickstart") {
                    if let p = confirmSpawn { confirmSpawn = nil; spawnAndInit(p) }
                }
                Button("Cancel", role: .cancel) { confirmSpawn = nil }
            } message: {
                Text("Runs launchctl kickstart for this daemon via SpringBoard's RC session, then initialises RC.")
            }
            .onAppear { refreshRunning() }
        }
    }

    // MARK: - Recommended section

    private var recommendedSection: some View {
        Section {
            ForEach(filteredRecommended, id: \.process) { entry in
                RecommendedRow(
                    entry:         entry,
                    isRouted:      entry.process == routedProcess,
                    isOverride:    selectedOverride == entry.process,
                    isRunning:     runningProcs.contains { $0.name == entry.process },
                    showSelect:    selectedOverride != nil,
                    onInit:        { initProcess(entry.process) },
                    onSpawn:       { confirmSpawn = entry.process },
                    onDestroy:     { rcio.destroyProc(entry.process) },
                    onRetry:       { rcio.resetProc(entry.process); initProcess(entry.process) },
                    onSelect:      { selectedOverride = entry.process; dismiss() }
                )
            }
        } header: {
            Text("Recommended")
        } footer: {
            if let path = pathContext {
                Text("Default route for \(URL(fileURLWithPath: path).lastPathComponent): \(routedProcess ?? "SpringBoard")")
            }
        }
    }

    // MARK: - All running section

    private var runningSection: some View {
        Section {
            if loadingProcs {
                HStack { Spacer(); ProgressView(); Text("Scanning…").foregroundColor(.secondary); Spacer() }
            } else if filteredRunning.isEmpty {
                Text(searchText.isEmpty ? "No processes found" : "No matches")
                    .foregroundColor(.secondary)
                    .font(.system(.body, design: .monospaced))
            } else {
                ForEach(filteredRunning) { proc in
                    RunningRow(
                        proc:       proc,
                        poolEntry:  rcio.pool[proc.name],
                        isRecommended: RemoteFileIO.recommendedProcesses.contains(proc.name),
                        showSelect: selectedOverride != nil,
                        onInit:    { initArbitrary(proc) },
                        onRetry:   { rcio.resetProc(proc.name); initArbitrary(proc) },
                        onSelect:  { selectedOverride = proc.name; dismiss() }
                    )
                }
            }
        } header: {
            HStack {
                Text("All Running (\(runningProcs.count))")
                Spacer()
                Text("R = root  M = mobile")
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.secondary)
            }
        } footer: {
            Text("Tap any process to attempt RC init. Root processes (R) have broader reach.")
        }
    }

    // MARK: - Filtered lists

    private var filteredRecommended: [RCPoolEntry] {
        let entries = RemoteFileIO.recommendedProcesses.compactMap { rcio.pool[$0] }
        guard !searchText.isEmpty else { return entries }
        return entries.filter { $0.process.localizedCaseInsensitiveContains(searchText) }
    }

    private var filteredRunning: [RunningProcess] {
        let base = runningProcs.filter { $0.pid > 1 }
        guard !searchText.isEmpty else { return base }
        return base.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }

    // MARK: - Actions

    private func initProcess(_ name: String) {
        guard mgr.dsready else { return }
        DispatchQueue.global(qos: .userInitiated).async { _ = rcio.rcProc(for: name) }
    }

    private func initArbitrary(_ proc: RunningProcess) {
        guard mgr.dsready else { return }
        rcio.addArbitraryProcess(proc.name)
        DispatchQueue.global(qos: .userInitiated).async {
            _ = rcio.rcProc(for: proc.name, spawnIfNeeded: false)
        }
    }

    private func spawnAndInit(_ name: String) {
        guard mgr.dsready else { return }
        DispatchQueue.global(qos: .userInitiated).async {
            _ = rcio.kickstart(service: name)
            Thread.sleep(forTimeInterval: 1.5)
            _ = rcio.rcProc(for: name)
        }
        DispatchQueue.global(qos: .background).async { self.refreshRunning() }
    }

    private func refreshRunning() {
        guard !loadingProcs else { return }
        DispatchQueue.main.async { loadingProcs = true }
        DispatchQueue.global(qos: .userInitiated).async {
            let procs = rcio.listRunningProcesses()
            DispatchQueue.main.async {
                self.runningProcs = procs
                self.loadingProcs = false
            }
        }
    }
}

// MARK: - Recommended row

private struct RecommendedRow: View {
    let entry:       RCPoolEntry
    let isRouted:    Bool
    let isOverride:  Bool
    let isRunning:   Bool
    let showSelect:  Bool
    let onInit:      () -> Void
    let onSpawn:     () -> Void
    let onDestroy:   () -> Void
    let onRetry:     () -> Void
    let onSelect:    () -> Void

    var body: some View {
        HStack(spacing: 10) {
            // State dot
            Circle()
                .fill(stateColor)
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    Text(entry.process)
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(isRouted ? .semibold : .regular)
                    if isRouted   { tag("routed",   .blue) }
                    if isOverride { tag("override", .orange) }
                    if !isRunning { tag("not running", .secondary) }
                }
                Text(entry.state.description)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(stateColor)
            }

            Spacer()

            HStack(spacing: 6) {
                actionButton
                if showSelect {
                    Button(isOverride ? "✓" : "Use") { onSelect() }
                        .font(.system(size: 12, design: .monospaced))
                        .buttonStyle(.bordered)
                        .tint(isOverride ? .green : .blue)
                        .controlSize(.mini)
                }
            }
        }
        .padding(.vertical, 2)
        .contentShape(Rectangle())
        .onTapGesture { if showSelect { onSelect() } }
    }

    @ViewBuilder
    private var actionButton: some View {
        switch entry.state {
        case .uninitialized:
            Button(isRunning ? "Init" : "Spawn") {
                isRunning ? onInit() : onSpawn()
            }
            .font(.system(size: 12, design: .monospaced))
            .buttonStyle(.bordered)
            .tint(.blue)
            .controlSize(.mini)

        case .initializing, .spawning:
            ProgressView().scaleEffect(0.7)

        case .ready:
            Button("Destroy") { onDestroy() }
                .font(.system(size: 12, design: .monospaced))
                .buttonStyle(.bordered)
                .tint(.red)
                .controlSize(.mini)

        case .failed:
            Button("Retry") { onRetry() }
                .font(.system(size: 12, design: .monospaced))
                .buttonStyle(.bordered)
                .tint(.orange)
                .controlSize(.mini)
        }
    }

    private var stateColor: Color {
        switch entry.state {
        case .ready:                return .green
        case .initializing, .spawning: return .blue
        case .failed:               return .red
        case .uninitialized:        return Color(.systemGray3)
        }
    }

    @ViewBuilder
    private func tag(_ text: String, _ color: Color) -> some View {
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

// MARK: - Running process row

private struct RunningRow: View {
    let proc:          RunningProcess
    let poolEntry:     RCPoolEntry?
    let isRecommended: Bool
    let showSelect:    Bool
    let onInit:        () -> Void
    let onRetry:       () -> Void
    let onSelect:      () -> Void

    private var isReady: Bool   { poolEntry?.state.isReady == true }
    private var isFailed: Bool  {
        if case .failed = poolEntry?.state { return true }; return false
    }
    private var isIniting: Bool {
        if case .initializing = poolEntry?.state { return true }
        if case .spawning     = poolEntry?.state { return true }
        return false
    }

    // Dot colour mirrors RecommendedRow.stateColor.
    // .spawning must be an explicit case here: poolEntry is Optional, so a
    // plain default would silently swallow nil (not running) and .spawning
    // (initing) with the same grey — exactly the bug isIniting was papering over.
    private var stateColor: Color {
        guard let state = poolEntry?.state else { return Color(.systemGray4) }
        switch state {
        case .ready:                   return .green
        case .initializing, .spawning: return .blue
        case .failed:                  return .red
        case .uninitialized:           return Color(.systemGray4)
        }
    }

    var body: some View {
        HStack(spacing: 10) {
            // State dot — was missing from RunningRow entirely.
            // Without it, spawning/initing processes showed no colour cue,
            // even though isIniting already detected the state correctly.
            Circle()
                .fill(stateColor)
                .frame(width: 8, height: 8)

            Text(proc.isRoot ? "R" : "M")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(proc.isRoot ? .orange : .secondary)
                .frame(width: 14)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 5) {
                    Text(proc.name)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                    if isRecommended { starTag }
                    if isReady       { readyTag }
                }
                Text("pid \(proc.pid) · uid \(proc.uid)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary)
            }

            Spacer()

            HStack(spacing: 6) {
                if isIniting {
                    ProgressView().scaleEffect(0.7)
                } else if isReady && showSelect {
                    Button("Use") { onSelect() }
                        .font(.system(size: 12, design: .monospaced))
                        .buttonStyle(.bordered)
                        .tint(.blue)
                        .controlSize(.mini)
                } else if isFailed {
                    Button("Retry") { onRetry() }
                        .font(.system(size: 12, design: .monospaced))
                        .buttonStyle(.bordered)
                        .tint(.orange)
                        .controlSize(.mini)
                } else if !isReady {
                    Button("Init RC") { onInit() }
                        .font(.system(size: 12, design: .monospaced))
                        .buttonStyle(.bordered)
                        .tint(isRecommended ? .blue : .purple)
                        .controlSize(.mini)
                }
            }
        }
        .padding(.vertical, 1)
    }

    private var starTag: some View {
        Text("★")
            .font(.system(size: 9, weight: .semibold, design: .monospaced))
            .foregroundColor(.blue)
            .padding(.horizontal, 3).padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: 3).fill(Color.blue.opacity(0.1)))
    }

    private var readyTag: some View {
        Text("ready")
            .font(.system(size: 9, weight: .semibold, design: .monospaced))
            .foregroundColor(.green)
            .padding(.horizontal, 4).padding(.vertical, 2)
            .background(
                RoundedRectangle(cornerRadius: 3)
                    .fill(Color.green.opacity(0.12))
                    .overlay(RoundedRectangle(cornerRadius: 3).stroke(Color.green.opacity(0.3), lineWidth: 0.5))
            )
    }
}
