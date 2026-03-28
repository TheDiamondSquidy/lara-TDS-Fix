//
//  lara.swift
//  lara
//
//  Created by ruter on 23.03.26.
//

import SwiftUI

@main
struct lara: App {
    init() {
        globallogger.capture()
    }

    var body: some Scene {
        WindowGroup {
            TabView {
                ContentView()
                    .tabItem {
                        Label("lara", systemImage: "ant.fill")
                    }

                LogsView(logger: globallogger)
                    .tabItem {
                        Label("Logs", systemImage: "text.document.fill")
                    }
            }
            .onAppear {
                init_offsets()
            }
        }
    }
}
