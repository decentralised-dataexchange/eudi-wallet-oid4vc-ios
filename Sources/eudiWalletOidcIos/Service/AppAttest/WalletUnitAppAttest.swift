//
//  WalletUnitAppAttest.swift
//  eudiWalletOidcIos
//
//  The App Attest key of a wallet unit for wallet provider protocol 2:
//  attested once, at the registration, and asserted on every later request.
//

import Foundation
import DeviceCheck

/// The device evidence of a wallet unit's requests.
///
/// The wallet provider knows the unit by one App Attest key. `attestKey` can
/// run only once for a key, so it runs at the registration only; every later
/// request carries an assertion of the same key, and the assertion counter
/// must go up from one request to the next. A second attested key for a
/// registered unit is refused (`app_attest_key_not_registered`): that needs a
/// new wallet unit.
///
/// A protocol so that tests can replace App Attest, which the simulator and
/// the test host do not have.
protocol WalletUnitAttester {
    /// The key id the wallet provider registered, or nil before the registration.
    var registeredKeyId: String? { get }

    /// Attests a key over `clientDataHash` for a registration. The key stays
    /// a candidate until ``markRegistered(keyId:)``.
    func attestation(clientDataHash: Data) async throws -> (attestation: Data, keyId: String)

    /// An assertion of the registered key over `clientDataHash`.
    func assertion(keyId: String, clientDataHash: Data) async throws -> Data

    /// The wallet provider accepted the registration with `keyId`.
    func markRegistered(keyId: String)

    /// Forgets the keys (a new wallet unit).
    func reset()
}

enum WalletUnitAttesterError: Error {
    /// The registered App Attest key no longer works on this device (a restored
    /// backup, a new phone): only a new wallet unit can go on.
    case keyLost
}

/// ``WalletUnitAttester`` on Apple App Attest. The key ids are kept in the
/// Keychain, this device only, readable after the first unlock so a request
/// can run in the background.
@available(iOS 14.0, *)
struct AppAttestWalletUnitAttester: WalletUnitAttester {

    /// The key the wallet provider registered.
    private static let registeredAccount = "WalletUnitAppAttestKeyId"
    /// A key generated but not yet attested (kept by ``AppAttestRetry`` across
    /// a throttled attempt, so the next attempt reuses it).
    private static let pendingAccount = "WalletUnitAppAttestPendingKeyId"

    private let service = DCAppAttestService.shared

    var registeredKeyId: String? { Self.read(account: Self.registeredAccount) }

    func attestation(clientDataHash: Data) async throws -> (attestation: Data, keyId: String) {
        try await AppAttestRetry.attest(service: service, clientDataHash: clientDataHash,
                                        keychainAccount: Self.pendingAccount)
    }

    func assertion(keyId: String, clientDataHash: Data) async throws -> Data {
        do {
            return try await AppAttestRetry.assertion(service: service, keyId: keyId, clientDataHash: clientDataHash)
        } catch where AppAttestRetry.isLostAssertionKey(error) {
            throw WalletUnitAttesterError.keyLost
        }
    }

    func markRegistered(keyId: String) {
        Self.write(keyId, account: Self.registeredAccount)
    }

    func reset() {
        Self.delete(account: Self.registeredAccount)
        AppAttestKeyStore.clearPendingKeyId(account: Self.pendingAccount)
    }

    // MARK: - Keychain

    private static func read(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let value = String(data: data, encoding: .utf8),
              !value.isEmpty else { return nil }
        return value
    }

    private static func write(_ value: String, account: String) {
        delete(account: account)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: Data(value.utf8)
        ]
        SecItemAdd(add as CFDictionary, nil)
    }

    private static func delete(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
