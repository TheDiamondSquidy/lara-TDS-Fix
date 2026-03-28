import SwiftUI

struct EditorView: View {
    @ObservedObject private var mgr = laramgr.shared
    private let systemPath = "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"

    private let origURL: URL
    private let modURL: URL

    @State private var mg: [String: Any] = [:]
    @State private var productType = ""
    @State private var customKey = ""
    @State private var customValue = ""
    @State private var customType: ValueType = .string
    @State private var status: String?

    init() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        origURL = docs.appendingPathComponent("OriginalMobileGestalt.plist")
        modURL = docs.appendingPathComponent("ModifiedMobileGestalt.plist")
    }

    var body: some View {
        Form {
            Section("MobileGestalt") {
                Toggle("Action Button", isOn: toggle("cT44WE1EohiwRzhsZ8xEsw"))
                Toggle("Dynamic Island", isOn: toggle("YlEtTtHlNesRBMal1CqRaA"))
                Toggle("Stage Manager", isOn: toggle("qeaj75wk3HF4DwQ8qbIi7g"))
                Toggle("Apple Intelligence", isOn: toggle("A62OafQ85EJAiiqKn4agtg"))
            }

            Section("Device Spoofing") {
                TextField("Product type", text: $productType)
                    .textInputAutocapitalization(.never)
            }

            Section("Custom Key") {
                TextField("Key", text: $customKey)
                TextField("Value", text: $customValue)

                Picker("Type", selection: $customType) {
                    ForEach(ValueType.allCases) { t in
                        Text(t.rawValue).tag(t)
                    }
                }

                Button("Set", action: setKey)
                Button("Remove", role: .destructive, action: removeKey)
            }

            Section("Manage") {
                Button("Apply", action: apply)
                    .disabled(!mgr.kfsready)

                Button("Reset", action: reset)

                ShareLink("Export Modified", item: modURL)
                ShareLink("Export Original", item: origURL)
            }
        }
        .navigationTitle("MobileGestalt")
        .alert("Status", isPresented: .constant(status != nil)) {
            Button("OK") { status = nil }
        } message: {
            Text(status ?? "")
        }
        .onAppear(perform: load)
    }

    private func cacheExtra() -> [String: Any] {
        mg["CacheExtra"] as? [String: Any] ?? [:]
    }

    private func toggle(_ key: String) -> Binding<Bool> {
        Binding(
            get: { cacheExtra()[key] != nil },
            set: { v in
                var c = cacheExtra()
                v ? (c[key] = 1) : c.removeValue(forKey: key)
                mg["CacheExtra"] = c
            }
        )
    }

    private func load() {
        let fm = FileManager.default
        let sys = URL(fileURLWithPath: systemPath)

        if !fm.fileExists(atPath: origURL.path) {
            try? fm.copyItem(at: sys, to: origURL)
        }
        if !fm.fileExists(atPath: modURL.path) {
            try? fm.copyItem(at: origURL, to: modURL)
        }

        mg = (NSDictionary(contentsOf: modURL) as? [String: Any]) ?? [:]
        productType = (cacheExtra()["h9jDsbgj7xIVeIQ8S3/X3Q"] as? String) ?? ""
    }

    private func apply() {
        var c = cacheExtra()
        if !productType.isEmpty { c["h9jDsbgj7xIVeIQ8S3/X3Q"] = productType }
        mg["CacheExtra"] = c

        do {
            let data = try PropertyListSerialization.data(fromPropertyList: mg, format: .xml, options: 0)
            try data.write(to: modURL)
            let ok = mgr.kfsoverwritewithdata(target: systemPath, data: data)
            status = ok ? "Applied." : "Failed."
        } catch {
            status = error.localizedDescription
        }
    }

    private func reset() {
        let fm = FileManager.default
        try? fm.removeItem(at: modURL)
        try? fm.copyItem(at: origURL, to: modURL)
        load()
        status = "Reset."
    }

    private func setKey() {
        var c = cacheExtra()

        let val: Any = switch customType {
        case .string: customValue
        case .int: Int(customValue) ?? 0
        case .bool: ["true","1","yes"].contains(customValue.lowercased())
        }

        c[customKey] = val
        mg["CacheExtra"] = c
        status = "Key set."
    }

    private func removeKey() {
        var c = cacheExtra()
        c.removeValue(forKey: customKey)
        mg["CacheExtra"] = c
        status = "Key removed."
    }
}

enum ValueType: String, CaseIterable, Identifiable {
    case string = "String"
    case int = "Int"
    case bool = "Bool"
    var id: String { rawValue }
}
