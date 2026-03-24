//
//  ContentView.swift
//  lara
//
//  Created by ruter on 23.03.26.
//

import SwiftUI
import Combine

struct ContentView: View {
    @ObservedObject private var controller = lara

    var body: some View {
        NavigationStack {
            List {
                Button(controller.running ? "Running..." : "Run Darksword") {
                    controller.start()
                }
                .disabled(controller.running)
                
                Button("Stop") {
                    controller.stop()
                }
                .disabled(!controller.running)
                
                Button("Clear Logs") {
                    controller.clear()
                }
            }
            .navigationTitle("lara")
        }
    }
}
