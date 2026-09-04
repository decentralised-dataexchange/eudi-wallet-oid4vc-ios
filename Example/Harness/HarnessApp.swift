//
//  HarnessApp.swift
//  Harness
//

import SwiftUI

/// A test harness for the issuance SDK, one function per button.
///
/// Scan or paste a credential offer, then run each step on its own and read what the SDK actually
/// did. Nothing runs implicitly, so a failing step can be repeated without redoing the ones before
/// it.
@main
struct HarnessApp: App {
    var body: some Scene {
        WindowGroup {
            HarnessView()
        }
    }
}
