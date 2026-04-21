//
//  ContentView.swift
//  lara
//
//  Created by ruter on 23.03.26.
//  Restructured: Home | Files | Tweaks | Logs | Jetsam
//

import SwiftUI
import UniformTypeIdentifiers

// MARK: - Method enum (unchanged)

struct ContentView: View {
    @ObservedObject private var mgr = laramgr.shared
    @State private var hasoffsets = true
    @State private var showsettings = false
    @State private var selectedmethod: method = .hybrid

    var body: some View {
        TabView {

            // MARK: Tab 1 — Home (exploit init)
            NavigationStack {
                homeContent
            }
            .tabItem { Label("Home", systemImage: "house") }

            // MARK: Tab 2 — Files (Santander + RC File Manager)
            NavigationStack {
                filesContent
            }
            .tabItem { Label("Files", systemImage: "folder") }

            // MARK: Tab 3 — Tweaks
            NavigationStack {
                tweaksContent
            }
            .tabItem { Label("Tweaks", systemImage: "wrench.and.screwdriver") }

            // MARK: Tab 4 — Logs
            NavigationStack {
                LogsView(mgr: mgr)
            }
            .tabItem { Label("Logs", systemImage: "scroll") }

            // MARK: Tab 5 — Jetsam
            NavigationStack {
                JetsamView()
            }
            .tabItem { Label("Jetsam", systemImage: "memorychip") }

        }
        .sheet(isPresented: $showsettings) {
            SettingsView(mgr: mgr, hasoffsets: $hasoffsets)
        }
        .onAppear { refreshselectedmethod() }
        .onReceive(NotificationCenter.default.publisher(for: UserDefaults.didChangeNotification)) { _ in
            refreshselectedmethod()
        }
    }

    // MARK: - Home content (exploit init — no tweaks mixed in)

    private var homeContent: some View {
        List {
            if !hasoffsets {
                Section("Setup") {
                    Text("Kernelcache offsets are missing. Download them in Settings.")
                        .foregroundColor(.secondary)
                    Button("Open Settings") { showsettings = true }
                }
            } else {
                // KRW section
                Section {
                    Button {
                        offsets_init()
                        mgr.run()
                    } label: {
                        if mgr.dsrunning {
                            HStack {
                                ProgressView(value: mgr.dsprogress)
                                    .progressViewStyle(.circular)
                                    .frame(width: 18, height: 18)
                                Text("Running...")
                                Spacer()
                                Text("\(Int(mgr.dsprogress * 100))%")
                            }
                        } else if mgr.dsready {
                            HStack {
                                Text("Ran Exploit")
                                Spacer()
                                Image(systemName: "checkmark.circle").foregroundColor(.green)
                            }
                        } else if mgr.dsattempted && mgr.dsfailed {
                            HStack {
                                Text("Exploit Failed")
                                Spacer()
                                Image(systemName: "xmark.circle").foregroundColor(.red)
                            }
                        } else {
                            Text("Run Exploit")
                        }
                    }
                    .disabled(mgr.dsrunning || mgr.dsready || isdebugged())

                    if mgr.dsready {
                        HStack {
                            Text("kernel_base:")
                            Spacer()
                            Text(String(format: "0x%llx", mgr.kernbase))
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        HStack {
                            Text("kernel_slide:")
                            Spacer()
                            Text(String(format: "0x%llx", mgr.kernslide))
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }

                    if isdebugged() {
                        Button("Detach") { exit(0) }.foregroundColor(.red)
                    }
                } header: {
                    Text("Kernel Read Write")
                } footer: {
                    if g_isunsupported {
                        Text("Your device/installation method may not be supported.")
                    }
                    if isdebugged() {
                        Text("Not available while debugger is attached.")
                    }
                }

                // VFS / SBX / Hybrid init section
                Section {
                    switch selectedmethod {
                    case .vfs:
                        vfsInitButton
                    case .sbx:
                        sbxInitButton
                    case .hybrid:
                        hybridInitButtons
                    }
                } header: {
                    Text(selectedmethod == .vfs ? "Virtual File System"
                         : selectedmethod == .sbx ? "Sandbox Escape"
                         : "Hybrid (SBX + VFS)")
                } footer: {
                    if selectedmethod == .sbx {
                        Text("Font Overwrite is only available in VFS or Hybrid mode.")
                    }
                }

                // RemoteCall init section
                #if !DISABLE_REMOTECALL
                Section {
                    Button {
                        mgr.logmsg("T")
                        mgr.rcinit(process: "SpringBoard", migbypass: false) { success in
                            if success {
                                mgr.logmsg("rc init succeeded!")
                                let pid = mgr.rccall(name: "getpid")
                                mgr.logmsg("remote getpid() returned: \(pid)")
                            } else {
                                mgr.logmsg("rc init failed")
                            }
                        }
                    } label: {
                        if mgr.rcrunning {
                            Text("Initialising RemoteCall...")
                        } else if !mgr.rcready {
                            Text("Initialise RemoteCall")
                        } else {
                            HStack {
                                Text("Initialised RemoteCall")
                                Spacer()
                                Image(systemName: "checkmark.circle").foregroundColor(.green)
                            }
                        }
                    }
                    .disabled(!mgr.dsready || mgr.rcready || isdebugged())

                    if mgr.rcready {
                        Button("Destroy RemoteCall") { mgr.rcdestroy() }
                    }

                    if isdebugged() {
                        Button("Detach") { exit(0) }.foregroundColor(.red)
                    }
                } header: {
                    Text("RemoteCall")
                } footer: {
                    if isdebugged() { Text("Not available when a debugger is attached.") }
                    Text("RemoteCall is still in development and may not work properly 100% of the time.")
                }
                .disabled(mgr.rcrunning)
                #endif

                // Other
                Section {
                    if mgr.dsready {
                        NavigationLink("Tools") { ToolsView() }
                    }
                    Button("Respring") { mgr.respring() }
                    Button("Panic!") { mgr.panic() }
                        .disabled(!mgr.dsready)
                } header: {
                    Text("Other")
                }
            }
        }
        .navigationTitle("lara")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { showsettings = true } label: {
                    Image(systemName: "gear")
                }
            }
        }
    }

    // MARK: - Init sub-views (VFS / SBX / Hybrid)

    @ViewBuilder
    private var vfsInitButton: some View {
        Button {
            mgr.vfsinit()
        } label: {
            if mgr.vfsrunning {
                HStack {
                    ProgressView(value: mgr.vfsprogress).progressViewStyle(.circular).frame(width: 18, height: 18)
                    Text("Initialising VFS...")
                    Spacer()
                    Text("\(Int(mgr.vfsprogress * 100))%")
                }
            } else if mgr.vfsready {
                HStack {
                    Text("Initialised VFS")
                    Spacer()
                    Image(systemName: "checkmark.circle").foregroundColor(.green)
                }
            } else if mgr.vfsattempted && mgr.vfsfailed {
                HStack {
                    Text("VFS Init Failed")
                    Spacer()
                    Image(systemName: "xmark.circle").foregroundColor(.red)
                }
            } else {
                Text("Initialise VFS")
            }
        }
        .disabled(!mgr.dsready || mgr.vfsready || mgr.vfsrunning)
    }

    @ViewBuilder
    private var sbxInitButton: some View {
        Button {
            mgr.sbxescape()
        } label: {
            if mgr.sbxrunning {
                HStack {
                    ProgressView().progressViewStyle(.circular).frame(width: 18, height: 18)
                    Text("Escaping Sandbox...")
                }
            } else if mgr.sbxready {
                HStack {
                    Text("Sandbox Escaped")
                    Spacer()
                    Image(systemName: "checkmark.circle").foregroundColor(.green)
                }
            } else if mgr.sbxattempted && mgr.sbxfailed {
                HStack {
                    Text("Sandbox Escape Failed")
                    Spacer()
                    Image(systemName: "xmark.circle").foregroundColor(.red)
                }
            } else {
                Text("Escape Sandbox")
            }
        }
        .disabled(!mgr.dsready || mgr.sbxready || mgr.sbxrunning)
    }

    @ViewBuilder
    private var hybridInitButtons: some View {
        if !mgr.sbxattempted {
            sbxInitButton
        } else {
            Button {
                mgr.vfsinit()
            } label: {
                if mgr.vfsrunning {
                    HStack {
                        ProgressView(value: mgr.vfsprogress).progressViewStyle(.circular).frame(width: 18, height: 18)
                        Text("Initialising VFS...")
                        Spacer()
                        Text("\(Int(mgr.vfsprogress * 100))%")
                    }
                } else if mgr.vfsready {
                    HStack {
                        Text("Initialised Hybrid")
                        Spacer()
                        Image(systemName: "checkmark.circle").foregroundColor(.green)
                    }
                } else if mgr.vfsattempted && mgr.vfsfailed {
                    HStack {
                        Text("VFS Init Failed")
                        Spacer()
                        Image(systemName: "xmark.circle").foregroundColor(.red)
                    }
                } else {
                    Text("Initialise VFS")
                }
            }
            .disabled(!mgr.dsready || mgr.vfsready || mgr.vfsrunning)
        }
    }

    // MARK: - Files tab (Santander + RC File Manager)

    private var filesContent: some View {
        List {
            Section {
                NavigationLink {
                    SantanderView(startPath: "/")
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "folder.fill")
                            .foregroundColor(.blue)
                            .frame(width: 28)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("File Manager")
                                .font(.body)
                            Text("Standard lara file browser")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }
                .disabled(!mgr.sbxready && !mgr.vfsready)

                NavigationLink {
                    FileManagerView()
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "folder.badge.gear")
                            .foregroundColor(.orange)
                            .frame(width: 28)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("RC File Manager")
                                .font(.body)
                            Text("RemoteCall-backed, full filesystem reach")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }
                .disabled(!mgr.dsready)
            } header: {
                Text("Choose a file browser")
            } footer: {
                if !mgr.sbxready && !mgr.vfsready {
                    Text("File Manager requires Sandbox Escape or VFS. Initialise on the Home tab.")
                }
                if !mgr.dsready {
                    Text("RC File Manager requires the exploit to be run first.")
                }
            }
        }
        .navigationTitle("Files")
    }

    // MARK: - Tweaks tab

    private var tweaksContent: some View {
        List {
            // RemoteCall tweaks — always at top if RC is ready
            #if !DISABLE_REMOTECALL
            if mgr.rcready {
                Section("RemoteCall") {
                    NavigationLink("SpringBoard Tweaks") {
                        RemoteView(mgr: mgr)
                    }
                }
            }
            #endif

            // Method-specific tweaks
            if selectedmethod == .vfs && mgr.vfsready {
                vfsTweaks

            } else if selectedmethod == .sbx && mgr.sbxready {
                sbxTweaks

            } else if selectedmethod == .hybrid && mgr.vfsready && mgr.sbxready {
                hybridTweaks

            } else {
                // Nothing ready yet
                Section {
                    HStack {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundColor(.secondary)
                        Text("Initialise the exploit on the Home tab first.")
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .navigationTitle("Tweaks")
    }

    @ViewBuilder
    private var vfsTweaks: some View {
        Section("VFS Tweaks") {
            NavigationLink("Font Overwrite") { FontPicker(mgr: mgr) }
            NavigationLink("Card Overwrite") { CardView() }
            NavigationLink("Custom Overwrite") { CustomView(mgr: mgr) }
            NavigationLink("DirtyZero (Broken)") { ZeroView(mgr: mgr) }
        }
    }

    @ViewBuilder
    private var sbxTweaks: some View {
        Section("Sandbox Tweaks") {
            NavigationLink("Card Overwrite") { CardView() }
            NavigationLink("3 App Bypass") { AppsView(mgr: mgr) }
            NavigationLink("VarClean") { VarCleanView() }
            NavigationLink("Unblacklist") { WhitelistView() }
        }
    }

    @ViewBuilder
    private var hybridTweaks: some View {
        Section("Tweaks") {
            NavigationLink("Font Overwrite") { FontPicker(mgr: mgr) }
            NavigationLink("Card Overwrite") { CardView() }
            NavigationLink("Custom Overwrite") { CustomView(mgr: mgr) }
            NavigationLink("MobileGestalt") { EditorView() }
            NavigationLink("3 App Bypass") { AppsView(mgr: mgr) }
            NavigationLink("VarClean") { VarCleanView() }
            NavigationLink("Whitelist") { WhitelistView() }
            NavigationLink("DirtyZero") { ZeroView(mgr: mgr) }

            // Hidden until ready
            if 1 == 2 {
                NavigationLink("Control Center") { CCView() }
                NavigationLink("DarkBoard") { DarkBoardView() }
                NavigationLink("Passcode Theme") { PasscodeView(mgr: mgr) }
            }
        }
    }

    // MARK: - Helpers

    private func refreshselectedmethod() {
        if let raw = UserDefaults.standard.string(forKey: "selectedmethod"),
           let m = method(rawValue: raw) {
            selectedmethod = m
        }
    }
}

// MARK: - Logs view

struct LogsView: View {
    @ObservedObject var mgr: laramgr
    @State private var autoscroll = true
    @State private var showClearConfirm = false

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                Text(mgr.log.isEmpty ? "(no log output yet)" : mgr.log)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(mgr.log.isEmpty ? .secondary : .primary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .id("logBottom")
                    .onChange(of: mgr.log) { _ in
                        if autoscroll {
                            withAnimation {
                                proxy.scrollTo("logBottom", anchor: .bottom)
                            }
                        }
                    }
            }
        }
        .navigationTitle("Logs")
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Toggle(isOn: $autoscroll) {
                    Image(systemName: "arrow.down.to.line")
                }
                .toggleStyle(.button)
                .tint(autoscroll ? .blue : .secondary)

                Button(role: .destructive) {
                    showClearConfirm = true
                } label: {
                    Image(systemName: "trash")
                }
            }
        }
        .alert("Clear log?", isPresented: $showClearConfirm) {
            Button("Clear", role: .destructive) { mgr.log = "" }
            Button("Cancel", role: .cancel) {}
        }
        .background(Color(.systemBackground))
    }
}
