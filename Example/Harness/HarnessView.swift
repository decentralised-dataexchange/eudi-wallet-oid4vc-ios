//
//  HarnessView.swift
//  Harness
//

import SwiftUI

struct HarnessView: View {

    @StateObject private var model = HarnessModel()
    @State private var isScanning = false

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    input
                    steps
                    Divider()
                    Text(model.output)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding()
            }
            .navigationTitle("EUDI Harness")
            .navigationBarTitleDisplayMode(.inline)
            .overlay { if model.isRunning { ProgressView().scaleEffect(1.4) } }
            .sheet(isPresented: $isScanning) {
                QRScannerView { scanned in
                    isScanning = false
                    model.onScanned(scanned)
                }
                .ignoresSafeArea()
            }
        }
        .navigationViewStyle(.stack)
    }

    private var input: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Pasting matters as much as scanning here: an offer link from a ticket or a log is
            // the common case when chasing a specific issuer's behaviour.
            TextEditor(text: $model.scannedInput)
                .font(.system(.caption, design: .monospaced))
                .frame(height: 72)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.secondary.opacity(0.4)))

            Button("Scan QR") { isScanning = true }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity)
        }
    }

    private var steps: some View {
        VStack(spacing: 8) {
            step("1 · Resolve credential offer") { await model.resolveOffer() }
            step("2 · Discover issuer metadata") { await model.discoverIssuer() }
            step("3 · Discover authorization server") { await model.discoverAuthServer() }
            step("4 · Request authorization") { await model.requestAuthorization() }

            Divider().padding(.vertical, 4)

            step("Run 1 → 4") { await model.runAll() }
            Button("Clear") { model.clear() }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity)
        }
    }

    private func step(_ title: String, action: @escaping () async -> Void) -> some View {
        Button(title) { Task { await action() } }
            .buttonStyle(.bordered)
            .frame(maxWidth: .infinity)
            .disabled(model.isRunning)
    }
}
