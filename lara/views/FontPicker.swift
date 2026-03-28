//
//  FontPicker.swift
//  lara
//
//  Created by ruter on 28.03.26.
//

import SwiftUI
import CoreText
import UIKit
import UniformTypeIdentifiers

struct FontPicker: View {
    @ObservedObject var mgr: laramgr
    @State private var showfontimporter: Bool = false

    private func applyfont(_ resource: String, label: String) {
        let success = mgr.kfsoverwrite(target: laramgr.fontpath, withBundledFont: resource)
        success ? mgr.logmsg("font changed to \(label)") : mgr.logmsg("failed to change font")
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Button {
                        applyfont("SFUI", label: "SFUI")
                    } label: {
                        Text("SFUI (Normal Font)")
                            .font(viewfont(resource: "SFUI", size: 17))
                    }
                    
                    Button {
                        applyfont("Comic Sans SFUI", label: "Comic Sans MS")
                    } label: {
                        Text("Comic Sans MS")
                            .font(viewfont(resource: "Comic Sans SFUI", size: 17))
                    }

                    Button {
                        applyfont("Chococooky", label: "Chococooky")
                    } label: {
                        Text("Chococooky")
                            .font(viewfont(resource: "Chococooky", size: 17))
                    }

                    Button {
                        applyfont("DejaVuSansMono", label: "DejaVuSansMono")
                    } label: {
                        Text("DejaVu Sans Mono")
                            .font(viewfont(resource: "DejaVuSansMono", size: 17))
                    }

                    Button {
                        applyfont("DejaVuSansCondensed", label: "DejaVuSansCondensed")
                    } label: {
                        Text("DejaVu Sans Condensed")
                            .font(viewfont(resource: "DejaVuSansCondensed", size: 17))
                    }

                    Button {
                        applyfont("DejaVuSerif", label: "DejaVuSerif")
                    } label: {
                        Text("DejaVu Serif")
                            .font(viewfont(resource: "DejaVuSerif", size: 17))
                    }

                    Button {
                        applyfont("FiraSans-Regular", label: "FiraSans")
                    } label: {
                        Text("Fira Sans")
                            .font(viewfont(resource: "FiraSans-Regular", size: 17))
                    }

                    Button {
                        applyfont("Go-Mono", label: "Go-Mono")
                    } label: {
                        Text("Go Mono")
                            .font(viewfont(resource: "Go-Mono", size: 17))
                    }

                    Button {
                        applyfont("Go-Regular", label: "Go-Regular")
                    } label: {
                        Text("Go Regular")
                            .font(viewfont(resource: "Go-Regular", size: 17))
                    }

                    Button {
                        applyfont("segoeui", label: "Segoe UI")
                    } label: {
                        Text("Segoe UI")
                            .font(viewfont(resource: "segoeui", size: 17))
                    }

                    Button("Custom Font (TTF)") {
                        showfontimporter = true
                    }
                } header: {
                    Text("Fonts")
                } footer: {
                    Text("Currently, only Comic Sans MS and SFUI work")
                }
            }
            .navigationTitle("Font Overwrite")
            .fileImporter(isPresented: $showfontimporter, allowedContentTypes: [UTType(filenameExtension: "ttf")!]) { result in
                do {
                    let url = try result.get()
                    let didAccess = url.startAccessingSecurityScopedResource()
                    defer {
                        if didAccess {
                            url.stopAccessingSecurityScopedResource()
                        }
                    }
                    let tmp = NSTemporaryDirectory() + "custom_font_\(UUID().uuidString).ttf"
                    try FileManager.default.copyItem(at: url, to: URL(fileURLWithPath: tmp))
                    let success = laramgr.shared.kfsoverwriteWithPatchedCustomFont(target: laramgr.fontpath, customFontPath: tmp)
                    try? FileManager.default.removeItem(atPath: tmp)
                    if success {
                        laramgr.shared.logmsg("font changed to custom font: \(url.lastPathComponent)")
                    } else {
                        laramgr.shared.logmsg("failed to change font to custom font")
                    }
                } catch {
                    laramgr.shared.logmsg("custom font import failed: \(error)")
                }
            }
        }
    }
}

private func viewfont(resource: String, size: CGFloat) -> Font {
    if let url = Bundle.main.url(forResource: resource, withExtension: "ttf", subdirectory: "fonts")
        ?? Bundle.main.url(forResource: resource, withExtension: "ttf", subdirectory: "Fonts")
        ?? Bundle.main.url(forResource: resource, withExtension: "ttf") {
        if let data = try? Data(contentsOf: url) as CFData,
           let provider = CGDataProvider(data: data),
           let cgFont = CGFont(provider) {
            let ctFont = CTFontCreateWithGraphicsFont(cgFont, size, nil, nil)
            let uiFont = ctFont as UIFont
            return Font(uiFont)
        }
    }
    return .system(size: size)
}
