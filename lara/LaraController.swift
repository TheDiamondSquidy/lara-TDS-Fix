//
//  LaraController.swift
//  lara
//

import Foundation
import Combine

let lara = LaraController()

final class LaraController: ObservableObject {
    @Published private(set) var running: Bool = false

    func start() {
        guard !running else { return }
        running = true

        DispatchQueue.global(qos: .userInitiated).async {
            _ = darksword_run { message in
                globallogger.log(message)
            }

            DispatchQueue.main.async {
                self.running = false
            }
        }
    }

    func stop() {
        darksword_request_stop()
        running = false
    }

    func clear() {
        globallogger.clear()
    }
}
