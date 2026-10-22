//
//  KeyBindingJwt.swift
//  eudiWalletOidcIos
//

import Foundation

/// The Key Binding JWT of an SD-JWT presentation (SD-JWT VC, OpenID4VP 1.0 Appendix B.3.6).
///
/// `aud` is the client identifier, `nonce` the request's nonce, `sd_hash` the hash of the
/// presented SD-JWT up to and including its last `~`. OpenID4VP section 8.4 adds
/// `transaction_data_hashes` and `transaction_data_hashes_alg`; the TS12 strong customer
/// authentication profile adds `response_mode`, `jti` and `amr`.
enum KeyBindingJwt {
    static let type = "kb+jwt"

    /// - Parameter presented: the SD-JWT to bind, ending with `~`.
    /// - Parameter scaResponseMode: set for an SCA flow; `jti` and `amr` go with it.
    static func sign(entryId: String, presented: String, key: SecureKeyProtocol, audience: String?, nonce: String?,
                     transactionDataHashes: TransactionDataHashes? = nil, scaResponseMode: String? = nil,
                     amr: [[String: String]]? = nil) throws -> String {
        var claims: [String: Any] = [
            "aud": audience ?? "",
            "nonce": nonce ?? "",
            "iat": Int(Date().timeIntervalSince1970),
            "sd_hash": SDJWTService.shared.calculateSHA256Hash(inputString: presented) ?? ""
        ]
        if let hashes = transactionDataHashes, !hashes.hashes.isEmpty {
            claims["transaction_data_hashes"] = hashes.hashes
            claims["transaction_data_hashes_alg"] = hashes.algorithm
        }
        if let scaResponseMode {
            claims["response_mode"] = scaResponseMode
            claims["jti"] = UUID().uuidString
            claims["amr"] = amr ?? AuthenticationMethods().amr()
        }
        let algorithm = key.keyStorageType == .eddsa ? "EdDSA" : "ES256"
        let header = Data((["alg": algorithm, "typ": type] as [String: Any]).toString()?.utf8 ?? "".utf8)
        guard let payload = claims.toString(),
              let jwt = key.sign(payload: payload, header: header, withKey: key.generateSecureKey()?.privateKey),
              !jwt.isEmpty else {
            throw PresentationError.keyBindingFailed(entryId)
        }
        return jwt
    }
}
