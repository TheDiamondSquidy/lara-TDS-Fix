//
//  Logger.swift
//  mowiwewgewawt
//  bacon why would you do that
//  teehee :3
//  yeah yeah teehee all you want 
//
//  Created by roooot on 15.11.25.
//

import Foundation
import Darwin
import Combine
import SwiftUI

let globallogger = Logger()

class Logger: ObservableObject {
    @Published var logs: [String] = []
    private var lastwasdivider = false
    private var pendingdivider = false
    private var stdoutPipe: Pipe?
    private var pendingLine = ""
    private var originalStdout: Int32 = -1
    private var originalStderr: Int32 = -1

    init() {}

    func log(_ message: String) {
        DispatchQueue.main.async {
            if self.pendingdivider {
                self.divider()
                self.pendingdivider = false
            }
            
            if self.lastwasdivider || self.logs.isEmpty {
                self.logs.append(message)
            } else {
                self.logs[self.logs.count - 1] += "\n" + message
            }

            self.lastwasdivider = false
        }

        emitToConsole(message)
    }

    func divider() {
        DispatchQueue.main.async {
            self.lastwasdivider = true
        }
    }
    
    func enclosedlog(_ message: String) {
        DispatchQueue.main.async {
            if !self.lastwasdivider && !self.logs.isEmpty {
                self.divider()
            }
            
            if self.lastwasdivider || self.logs.isEmpty {
                self.logs.append(message)
            } else {
                self.logs[self.logs.count - 1] += "\n" + message
            }
            
            self.lastwasdivider = false
            self.pendingdivider = true
        }
    }
    
    func flushdivider() {
        DispatchQueue.main.async {
            if self.pendingdivider {
                self.divider()
                self.pendingdivider = false
            }
        }
    }

    func clear() {
        DispatchQueue.main.async {
            self.logs.removeAll()
            self.lastwasdivider = false
            self.pendingdivider = false
        }
    }

    func startCapture() {
        if stdoutPipe != nil { return }

        let pipe = Pipe()
        stdoutPipe = pipe

        originalStdout = dup(STDOUT_FILENO)
        originalStderr = dup(STDERR_FILENO)

        setvbuf(stdout, nil, _IOLBF, 0)
        setvbuf(stderr, nil, _IOLBF, 0)

        dup2(pipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)
        dup2(pipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO)

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { return }
            guard let chunk = String(data: data, encoding: .utf8), !chunk.isEmpty else { return }
            self?.appendRaw(chunk)
        }
    }

    private func appendRaw(_ chunk: String) {
        var text = pendingLine + chunk
        var lines = text.components(separatedBy: "\n")
        pendingLine = lines.removeLast()
        if !lines.isEmpty {
            DispatchQueue.main.async {
                self.logs.append(contentsOf: lines)
            }
        }
    }

    private func emitToConsole(_ message: String) {
        guard originalStdout != -1 else { return }
        let line = message + "\n"
        line.withCString { ptr in
            _ = Darwin.write(originalStdout, ptr, strlen(ptr))
        }
    }
}

struct LogsView: View {
    @ObservedObject var logger: Logger

    var body: some View {
        NavigationView {
            List {
                ForEach(logger.logs, id: \.self) { log in
                    Text(log)
                        .font(.system(size: 13, design: .monospaced))
                        .lineSpacing(1)
                        .listRowInsets(EdgeInsets(top: 2, leading: 8, bottom: 2, trailing: 8))
                        .onTapGesture {
                            UIPasteboard.general.string = log
                            UIImpactFeedbackGenerator(style: .light).impactOccurred()
                        }
                }
            }
            .listStyle(.plain)
            .navigationTitle("Logs")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Clear") { logger.logs.removeAll() }
                        .foregroundColor(.red)
                }
            }
        }
    }
}
