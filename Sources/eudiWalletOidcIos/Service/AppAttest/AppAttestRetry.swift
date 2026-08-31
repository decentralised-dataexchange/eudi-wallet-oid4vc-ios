//
//  AppAttestRetry.swift
//  eudiWalletOidcIos
//
//  Error-aware attestation for Apple App Attest.
//
//  Apple tracks a risk metric per device, and DCError documents how to avoid
//  eroding it: when attestKey fails with `serverUnavailable`, "try the
//  attestation again later using the same key and the same value for the
//  clientDataHash parameter. Retrying with the same inputs helps to preserve
//  the risk metric for a given device."
//
//  So the two failure modes need opposite handling, and a blanket catch gets
//  one of them wrong:
//
//   - `invalidKey`        the key was already attested (attestKey is once per
//                         key) or was rejected. A new key is the only way
//                         forward.
//   - `serverUnavailable` the service could not be reached or is throttling.
//                         The key is still good. Regenerating here is what
//                         costs the device its risk metric.
//
//  An un-attested key is kept in the Keychain between attempts, so a throttled
//  flow resumes on the same key instead of minting another one.
//

import Foundation
import DeviceCheck

@available(iOS 14.0, *)
enum AppAttestRetry {

    /// Backoff between `serverUnavailable` retries. Short: this sits inside a
    /// user-visible issuance flow.
    private static let backoffSeconds: [UInt64] = [1, 3]

    /// Attest `clientDataHash`, reusing any key left un-attested by an earlier
    /// throttled attempt. Returns the attestation object and the key id it was
    /// produced for. Throws the last DCError if every attempt fails.
    static func attest(
        service: DCAppAttestService,
        clientDataHash: Data,
        keychainAccount: String
    ) async throws -> (attestation: Data, keyId: String) {
        var keyId: String
        if let pending = AppAttestKeyStore.pendingKeyId(account: keychainAccount) {
            keyId = pending
        } else {
            keyId = try await generateKey(service: service, account: keychainAccount)
        }
        var lastError: Error?

        for attempt in 0...backoffSeconds.count {
            do {
                let attestation = try await attestKey(service: service, keyId: keyId, clientDataHash: clientDataHash)
                // Consumed: this key can never be attested again.
                AppAttestKeyStore.clearPendingKeyId(account: keychainAccount)
                return (attestation, keyId)
            } catch {
                lastError = error
                switch dcError(error) {
                case .some(.serverUnavailable):
                    guard attempt < backoffSeconds.count else {
                        // Leave the key pending so the next flow reuses it
                        // rather than minting another.
                        print("KaWatch: App Attest unavailable after \(attempt + 1) attempts - keeping key \(keyId) for the next attempt")
                        throw error
                    }
                    print("KaWatch: App Attest server unavailable - retrying the SAME key and clientDataHash in \(backoffSeconds[attempt])s")
                    try? await Task.sleep(nanoseconds: backoffSeconds[attempt] * 1_000_000_000)
                case .some(.invalidKey):
                    // Already attested or rejected: a new key is the only way on.
                    print("KaWatch: App Attest key \(keyId) is invalid (already attested or rejected) - generating a new one")
                    AppAttestKeyStore.clearPendingKeyId(account: keychainAccount)
                    keyId = try await generateKey(service: service, account: keychainAccount)
                default:
                    // featureUnsupported, invalidInput, unknown: retrying cannot help.
                    print("KaWatch: App Attest failed, not retryable: \(error)")
                    throw error
                }
            }
        }
        throw lastError ?? NSError(domain: "AppAttest", code: -1,
                                   userInfo: [NSLocalizedDescriptionKey: "Attestation failed"])
    }

    /// Attest a key the caller owns, retrying only `serverUnavailable` and only
    /// with identical inputs. Every other error is thrown straight through so
    /// the caller can decide - `invalidKey` in particular means the caller must
    /// mint a new key, which only it knows how to persist.
    static func attestExistingKey(
        service: DCAppAttestService,
        keyId: String,
        clientDataHash: Data
    ) async throws -> String {
        var lastError: Error?
        for attempt in 0...backoffSeconds.count {
            do {
                return try await attestKey(service: service, keyId: keyId, clientDataHash: clientDataHash)
                    .base64EncodedString()
            } catch {
                lastError = error
                guard dcError(error) == .serverUnavailable, attempt < backoffSeconds.count else { throw error }
                print("App Attest server unavailable - retrying the SAME key and clientDataHash in \(backoffSeconds[attempt])s")
                try? await Task.sleep(nanoseconds: backoffSeconds[attempt] * 1_000_000_000)
            }
        }
        throw lastError ?? NSError(domain: "AppAttest", code: -1,
                                   userInfo: [NSLocalizedDescriptionKey: "Attestation failed"])
    }

    private static func dcError(_ error: Error) -> DCError.Code? {
        let nsError = error as NSError
        guard nsError.domain == DCErrorDomain else { return nil }
        return DCError.Code(rawValue: nsError.code)
    }

    private static func generateKey(service: DCAppAttestService, account: String) async throws -> String {
        let keyId: String = try await withCheckedThrowingContinuation { continuation in
            service.generateKey { keyId, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let keyId = keyId {
                    continuation.resume(returning: keyId)
                } else {
                    continuation.resume(throwing: NSError(domain: "AppAttest", code: -1,
                                                          userInfo: [NSLocalizedDescriptionKey: "Key generation failed"]))
                }
            }
        }
        AppAttestKeyStore.storePendingKeyId(keyId, account: account)
        return keyId
    }

    private static func attestKey(service: DCAppAttestService, keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let attestation = attestation {
                    continuation.resume(returning: attestation)
                } else {
                    continuation.resume(throwing: NSError(domain: "AppAttest", code: -1,
                                                          userInfo: [NSLocalizedDescriptionKey: "Attestation failed"]))
                }
            }
        }
    }
}

/// Keychain slot for an App Attest key that has been generated but not yet
/// successfully attested. Cleared as soon as an attestation succeeds, because
/// a key can only be attested once.
enum AppAttestKeyStore {

    static func pendingKeyId(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let keyId = String(data: data, encoding: .utf8),
              !keyId.isEmpty else { return nil }
        return keyId
    }

    static func storePendingKeyId(_ keyId: String, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: Data(keyId.utf8)
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    static func clearPendingKeyId(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
