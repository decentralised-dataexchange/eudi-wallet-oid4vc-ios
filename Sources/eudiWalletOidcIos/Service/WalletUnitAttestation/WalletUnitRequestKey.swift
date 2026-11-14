//
//  WalletUnitRequestKey.swift
//  eudiWalletOidcIos
//
//  The request key of a wallet unit: the P-256 key that signs every wallet
//  provider protocol 2 request (RFC 9421). The wallet provider finds the unit
//  by the RFC 7638 thumbprint of this key, the `keyid` of the signature.
//

import Foundation
import CryptoKit

/// A key that signs a request: its public JWK, and a raw ECDSA P-256 SHA-256
/// signature (r || s, 64 bytes) over any bytes.
///
/// `SecureKeyProtocol` signs JWS only, so the request signature needs its own
/// small abstraction. Tests use ``SoftwareRequestKey``; the app uses the
/// Secure Enclave key of ``WalletUnitRequestKeyStore``.
protocol RequestSigningKey {
    var publicJWK: [String: Any] { get }
    func signRaw(_ data: Data) throws -> Data
}

extension RequestSigningKey {
    /// The RFC 7638 thumbprint of the public key: the `keyid` of the signature.
    var keyId: String? { JWKThumbprint.rfc7638(of: publicJWK) }
}

/// The public JWK of a P-256 key from its raw representation (x || y).
private func p256PublicJWK(raw: Data) -> [String: Any] {
    [
        "kty": "EC",
        "crv": "P-256",
        "x": raw.prefix(32).base64URLEncodedString(),
        "y": raw.suffix(32).base64URLEncodedString()
    ]
}

/// The request key in the Secure Enclave. The private key never leaves it.
struct SecureEnclaveRequestKey: RequestSigningKey {
    let privateKey: CryptoKit.SecureEnclave.P256.Signing.PrivateKey

    var publicJWK: [String: Any] { p256PublicJWK(raw: privateKey.publicKey.rawRepresentation) }

    func signRaw(_ data: Data) throws -> Data {
        try privateKey.signature(for: data).rawRepresentation
    }
}

/// A software request key, for tests (the Secure Enclave and the Keychain are
/// not available to the test host).
struct SoftwareRequestKey: RequestSigningKey {
    let privateKey: P256.Signing.PrivateKey

    var publicJWK: [String: Any] { p256PublicJWK(raw: privateKey.publicKey.rawRepresentation) }

    func signRaw(_ data: Data) throws -> Data {
        try privateKey.signature(for: data).rawRepresentation
    }
}

enum WalletUnitRequestKeyError: Error {
    /// The device has no Secure Enclave (a simulator, a very old device).
    case secureEnclaveUnavailable
    /// The Keychain refused to store the key.
    case keychain(OSStatus)
}

/// Where the client finds the request key: the Secure Enclave store in the
/// app, a software key in tests.
protocol WalletUnitRequestKeys {
    func current() -> RequestSigningKey?
    func make() throws -> RequestSigningKey
    func remove()
}

/// ``WalletUnitRequestKeys`` on ``WalletUnitRequestKeyStore``.
struct SecureEnclaveRequestKeys: WalletUnitRequestKeys {
    func current() -> RequestSigningKey? { WalletUnitRequestKeyStore.current() }
    func make() throws -> RequestSigningKey { try WalletUnitRequestKeyStore.make() }
    func remove() { WalletUnitRequestKeyStore.remove() }
}

/// The one request key of the wallet unit, in the Secure Enclave. The Keychain
/// keeps its `dataRepresentation` (an encrypted handle that only this device's
/// Secure Enclave can use), this device only, so the key never moves to a new
/// phone or into a backup: a missing key means a new wallet unit.
///
/// Readable after the first unlock, so a WIA request can run in the background.
enum WalletUnitRequestKeyStore {

    private static let account = "WalletUnitRequestKey"

    /// The stored request key, or nil when there is none.
    static func current() -> SecureEnclaveRequestKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let privateKey = try? CryptoKit.SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
        else { return nil }
        return SecureEnclaveRequestKey(privateKey: privateKey)
    }

    /// Makes a new request key in the Secure Enclave and stores it, replacing
    /// any earlier one.
    static func make() throws -> SecureEnclaveRequestKey {
        guard CryptoKit.SecureEnclave.isAvailable else { throw WalletUnitRequestKeyError.secureEnclaveUnavailable }
        let privateKey = try CryptoKit.SecureEnclave.P256.Signing.PrivateKey()
        remove()
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: privateKey.dataRepresentation
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw WalletUnitRequestKeyError.keychain(status) }
        return SecureEnclaveRequestKey(privateKey: privateKey)
    }

    /// Deletes the request key (a new wallet unit, a wiped wallet).
    static func remove() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
