//
//  ProcessSelectorView.swift
//  lara
//
//  Single-pane unified process picker.
//  Filter chips: All · Recommended · Live · Activated · Not Init
//  Sort chips:   A–Z · Ready First · Uninit First
//
//  "Isolate" sets the process as the sole RC override for the file manager.
//  Isolating a process automatically un-isolates every other one (single binding).
//

import SwiftUI

// MARK: - Filter / Sort enums

private enum ProcFilter: String, CaseIterable, Identifiable {
    case all          = "All"
    case recommended  = "Recommended"
    case live         = "Live"
    case activated    = "Activated"
    case notActivated = "Not Init"
    var id: String { rawValue }
}

private enum ProcSort: String, CaseIterable, Identifiable {
    case alpha       = "A–Z"
    case readyFirst  = "Ready First"
    case uninitFirst = "Uninit First"
    var id: String { rawValue }
}

// MARK: - Unified row model

private struct UnifiedProcess: Identifiable {
    let id           = UUID()
    let name:        String
    let isRecommended: Bool
    let isRunning:   Bool
    let pid:         UInt32?
    let uid:         UInt32?
    let poolEntry:   RCPoolEntry?

    var isRoot:  Bool { (uid ?? 1) == 0 }
    var isReady: Bool { poolEntry?.state.isReady == true }
    var isFailed: Bool {
        guard case .failed = poolEntry?.state else { return false }
        return true
    }
    var isIniting: Bool {
        if case .initializing = poolEntry?.state { return true }
        if case .spawning     = poolEntry?.state { return true }
        return false
    }
    var stateColor: Color {
        guard let state = poolEntry?.state else { return Color(.systemGray4) }
        switch state {
        case .ready:                   return .green
        case .initializing, .spawning: return .blue
        case .failed:                  return .red
        case .uninitialized:           return Color(.systemGray4)
        }
    }
    var stateLabel: String {
        if !isRunning { return "not running" }
        guard let entry = poolEntry else { return "not init" }
        return entry.state.description
    }
}

// MARK: - ProcessSelectorView

struct ProcessSelectorView: View {
    @ObservedObject private var rcio = RemoteFileIO.shared
    @ObservedObject private var mgr  = laramgr.shared

    let pathContext: String?
    @Binding var selectedOverride: String?

    @Environment(\.dismiss) private var dismiss

    @State private var runningProcs:  [RunningProcess] = []
    @State private var loadingProcs   = false
    @State private var searchText     = ""
    @State private var activeFilter:  ProcFilter = .all
    @State private var activeSort:    ProcSort   = .readyFirst
    @State private var confirmSpawn:  String?

    private var routedProcess: String? {
        pathContext.map { rcio.rcBestProcess(for: $0) }
    }

    // MARK: - Unified data

    private var allUnified: [UnifiedProcess] {
        var seen   = Set<String>()
        var result = [UnifiedProcess]()

        // Recommended pool entries first (whether running or not)
        for name in RemoteFileIO.recommendedProcesses {
            seen.insert(name)
            let running = runningProcs.first { $0.name == name }
            result.append(UnifiedProcess(
                name:          name,
                isRecommended: true,
                isRunning:     running != nil,
                pid:           running?.pid,
                uid:           running?.uid,
                poolEntry:     rcio.pool[name]
            ))
        }

        // Remaining live processes not in recommended list
        for proc in runningProcs where proc.pid > 1 && !seen.contains(proc.name) {
            seen.insert(proc.name)
            result.append(UnifiedProcess(
                name:          proc.name,
                isRecommended: false,
                isRunning:     true,
                pid:           proc.pid,
                uid:           proc.uid,
                poolEntry:     rcio.pool[proc.name]
            ))
        }
        return result
    }

    private var filteredAndSorted: [UnifiedProcess] {
        var list = allUnified
        switch activeFilter {
        case .all:          break
        case .recommended:  list = list.filter { $0.isRecommended }
        case .live:         list = list.filter { $0.isRunning }
        case .activated:    list = list.filter { $0.isReady }
        case .notActivated: list = list.filter { !$0.isReady }
        }
        if !searchText.isEmpty {
            list = list.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
        }
        switch activeSort {
        case .alpha:
            list.sort { $0.name.lowercased() < $1.name.lowercased() }
        case .readyFirst:
            list.sort {
                let score: (UnifiedProcess) -> Int = { p in
                    p.isReady ? 0 : (p.isIniting ? 1 : (p.isFailed ? 2 : 3))
                }
                return score($0) != score($1)
                    ? score($0) < score($1)
                    : $0.name.lowercased() < $1.name.lowercased()
            }
        case .uninitFirst:
            list.sort {
                let uninit: (UnifiedProcess) -> Int = { (!$0.isReady && !$0.isIniting) ? 0 : 1 }
                return uninit($0) != uninit($1)
                    ? uninit($0) < uninit($1)
                    : $0.name.lowercased() < $1.name.lowercased()
            }
        }
        return list
    }

    // MARK: - Body

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                filterBar
                Divider()
                sortBar
                Divider()
                processListContent
            }
            .searchable(text: $searchText, prompt: "Search processes")
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
            .alert("Spawn \(confirmSpawn ?? "")?",
                   isPresented: .constant(confirmSpawn != nil)) {
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

    // MARK: - Filter bar

    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(ProcFilter.allCases) { filter in
                    filterChip(
                        title:  filter.rawValue,
                        active: activeFilter == filter
                    ) { withAnimation(.easeInOut(duration: 0.15)) { activeFilter = filter } }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
        .background(Color(.secondarySystemBackground))
    }

    // MARK: - Sort bar

    private var sortBar: some View {
        HStack(spacing: 8) {
            Text("Sort:")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.secondary)
            ForEach(ProcSort.allCases) { sort in
                filterChip(
                    title:   sort.rawValue,
                    active:  activeSort == sort,
                    compact: true
                ) { withAnimation(.easeInOut(duration: 0.15)) { activeSort = sort } }
            }
            Spacer()
            // Route hint
            if let path = pathContext {
                Text("→ \(routedProcess ?? "SpringBoard")")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(Color(.tertiarySystemBackground))
    }

    @ViewBuilder
    private func filterChip(title: String, active: Bool, compact: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.system(
                    size:   compact ? 10 : 12,
                    weight: active  ? .semibold : .regular,
                    design: .monospaced))
                .foregroundColor(active ? (compact ? .blue : .white) : .primary)
                .padding(.horizontal, compact ? 7 : 10)
                .padding(.vertical,   compact ? 3  : 5)
                .background(
                    RoundedRectangle(cornerRadius: compact ? 4 : 6)
                        .fill(active
                              ? (compact ? Color.blue.opacity(0.1) : Color.blue)
                              : Color(.tertiarySystemBackground))
                        .overlay(
                            RoundedRectangle(cornerRadius: compact ? 4 : 6)
                                .stroke(active
                                        ? (compact ? Color.blue.opacity(0.5) : Color.blue)
                                        : Color.secondary.opacity(0.3),
                                        lineWidth: 0.5)
                        )
                )
        }
        .buttonStyle(.plain)
    }

    // MARK: - Process list

    private var processListContent: some View {
        Group {
            if loadingProcs && runningProcs.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    ProgressView()
                    Text("Scanning processes…")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(.secondary)
                    Spacer()
                }
            } else {
                let items = filteredAndSorted
                if items.isEmpty {
                    VStack(spacing: 12) {
                        Spacer()
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 32))
                            .foregroundColor(.secondary)
                        Text(searchText.isEmpty
                             ?: "No processes match "\(activeFilter.rawValue)""
                             : "No results for "\(searchText)"")
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                } else {
                    List {
                        // Stats header
                        Section {
                            ForEach(items) { proc in
                                unifiedRow(proc)
                            }
                        } header: {
                            HStack {
                                Text("\(items.count) processes")
                                    .font(.system(size: 10, design: .monospaced))
                                    .textCase(nil)
                                Spacer()
                                let ready = items.filter { $0.isReady }.count
                                if ready > 0 {
                                    Text("\(ready) ready")
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(.green)
                                        .textCase(nil)
                                }
                                Text("R=root  M=mobile")
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundColor(.secondary)
                                    .textCase(nil)
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                    .refreshable { refreshRunning() }
                }
            }
        }
    }

    // MARK: - Unified row

    @ViewBuilder
    private func unifiedRow(_ proc: UnifiedProcess) -> some View {
        HStack(spacing: 10) {
            // State dot
            Circle()
                .fill(proc.stateColor)
                .frame(width: 8, height: 8)

            // Privilege badge
            Text(proc.isRoot ? "R" : "M")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(proc.isRoot ? .orange : Color(.systemGray))
                .frame(width: 14)

            // Name + meta
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    Text(proc.name)
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(proc.name == routedProcess ? .semibold : .regular)
                        .lineLimit(1)

                    if proc.name == routedProcess    { inlineTag("routed",   .blue) }
                    if selectedOverride == proc.name { inlineTag("isolated", .orange) }
                    if proc.isRecommended            { inlineTag("★",        .blue) }
                    if !proc.isRunning               { inlineTag("offline",  Color(.systemGray2)) }
                }

                HStack(spacing: 6) {
                    if let pid = proc.pid {
                        Text("pid \(pid)")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                    Text(proc.stateLabel)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(proc.stateColor)
                }
            }

            Spacer()

            // Action buttons column
            HStack(spacing: 6) {
                rcActionButton(proc)
                isolateButton(proc)
            }
        }
        .padding(.vertical, 2)
        .contentShape(Rectangle())
    }

    @ViewBuilder
    private func rcActionButton(_ proc: UnifiedProcess) -> some View {
        if proc.isIniting {
            ProgressView().scaleEffect(0.65)
        } else if proc.isReady {
            Button("Destroy") {
                rcio.destroyProc(proc.name)
                if selectedOverride == proc.name { selectedOverride = nil }
            }
            .font(.system(size: 11, design: .monospaced))
            .buttonStyle(.bordered)
            .tint(.red)
            .controlSize(.mini)
        } else if proc.isFailed {
            Button("Retry") {
                rcio.resetProc(proc.name)
                initProc(proc)
            }
            .font(.system(size: 11, design: .monospaced))
            .buttonStyle(.bordered)
            .tint(.orange)
            .controlSize(.mini)
        } else {
            Button(proc.isRunning ? "Init" : "Spawn") {
                if proc.isRunning { initProc(proc) } else { confirmSpawn = proc.name }
            }
            .font(.system(size: 11, design: .monospaced))
            .buttonStyle(.bordered)
            .tint(.blue)
            .controlSize(.mini)
            .disabled(!mgr.dsready)
        }
    }

    @ViewBuilder
    private func isolateButton(_ proc: UnifiedProcess) -> some View {
        let isIsolated = selectedOverride == proc.name
        Button(isIsolated ? "✓ Isolated" : "Isolate") {
            if isIsolated {
                selectedOverride = nil   // clear isolation
            } else {
                selectedOverride = proc.name   // isolate (dismisses & sets override)
                dismiss()
            }
        }
        .font(.system(size: 11, design: .monospaced))
        .buttonStyle(.bordered)
        .tint(isIsolated ? .green : .purple)
        .controlSize(.mini)
    }

    @ViewBuilder
    private func inlineTag(_ text: String, _ color: Color) -> some View {
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

    // MARK: - Actions

    private func initProc(_ proc: UnifiedProcess) {
        guard mgr.dsready else { return }
        if !proc.isRecommended { rcio.addArbitraryProcess(proc.name) }
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
        DispatchQueue.global(qos: .background).async { refreshRunning() }
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
