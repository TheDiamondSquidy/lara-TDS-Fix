//
//  laraApp.swift
//  lara
//
//  Created by ruter on 23.03.26.
//

import SwiftUI

@main
struct laraApp: App {
    init() {
        globallogger.startCapture()
    }

    var body: some Scene {
        WindowGroup {
            TabView {
                Tab("lara", systemImage: "ant.fill") {
                    ContentView()
                }

                Tab("Logs", systemImage: "text.document.fill") {
                    LogsView(logger: globallogger)
                }
            }
        }
    }
}
