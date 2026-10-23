//
//  ResponseEncrypter.swift
//  eudiWalletOidcIos
//

import Foundation
import JOSESwift

/// OpenID4VP 1.0 section 8.3, encrypted responses: "implementations MUST use an unsigned, encrypted
/// JWT", the key comes from the client metadata `jwks`, "the JWE alg algorithm used MUST be equal to
/// the alg value of the chosen jwk", the `kid` is copied, and "the JWE enc content encryption
/// algorithm used is obtained from the encrypted_response_enc_values_supported parameter ...
/// allowing for the default value of A128GCM when not explicitly set".
///
/// The draft names `authorization_encrypted_response_alg` and `authorization_encrypted_response_enc`
/// are read when the 1.0 ones are absent. `apu` carries the client id and `apv` the nonce, which is
/// what the ISO 18013-7 Annex B session transcript expects to find.
struct ResponseEncrypter {

    private static let encValuesSupported = "encrypted_response_enc_values_supported"
    private static let legacyEncValuesSupported = "authorization_encrypted_response_enc_values_supported"
    private static let draftAlg = "authorization_encrypted_response_alg"
    private static let draftEnc = "authorization_encrypted_response_enc"
    private static let supportedAlgorithms: [KeyManagementAlgorithm] = [.ECDH_ES, .ECDH_ES_A128KW, .ECDH_ES_A256KW]
    private static let preference: [ContentEncryptionAlgorithm] = [.A128CBCHS256, .A128GCM, .A256GCM, .A256CBCHS512]

    /// - Throws: `SubmissionError.noEncryptionKey`, `.encryptionUnsupported` or `.encryptionFailed`
    func encrypt(_ parameters: [String: Any], _ request: PresentationRequest) async throws -> String {
        let metadata = request.clientMetaData?.data(using: .utf8)
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
        let key = try await selectKey(metadata)
        let algorithm = try selectAlgorithm(key["alg"] as? String, metadata)
        let encryption = try selectEncryption(metadata)
        guard let x = key["x"] as? String, let y = key["y"] as? String else { throw SubmissionError.noEncryptionKey }
        let kid = (key["kid"] as? String).flatMap { $0.isEmpty ? nil : $0 }

        do {
            var header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: encryption)
            header.kid = kid
            if let nonce = request.nonce, !nonce.isEmpty { header.apv = Data(nonce.utf8).base64URLEncodedString() }
            if let clientId = request.clientId, !clientId.isEmpty { header.apu = Data(clientId.utf8).base64URLEncodedString() }
            let publicKey = ECPublicKey(crv: .P256, x: x, y: y, additionalParameters: kid.map { ["kid": $0] } ?? [:])
            let payload = try JSONSerialization.data(withJSONObject: parameters)
            guard let encrypter = Encrypter(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: encryption,
                                            encryptionKey: publicKey) else { throw SubmissionError.encryptionFailed }
            return try JWE(header: header, payload: Payload(payload), encrypter: encrypter).compactSerializedString
        } catch {
            throw SubmissionError.encryptionFailed
        }
    }

    /// The P-256 encryption key: from `jwks_uri`, else from `jwks` with `use: enc` first, then a key
    /// with no `use`. Never a signing key.
    private func selectKey(_ metadata: [String: Any]) async throws -> [String: Any] {
        if let uri = metadata["jwks_uri"] as? String, !uri.isEmpty {
            let fetched = await ProcessJWKFromJwksUri.fetchJwkData(kid: nil, jwksUri: uri, keyUse: "enc")
            if fetched["x"] != nil { return fetched }
        }
        let keys = ((metadata["jwks"] as? [String: Any])?["keys"] as? [[String: Any]] ?? [])
            .filter { $0["crv"] as? String == "P-256" }
        guard let key = keys.first(where: { $0["use"] as? String == "enc" }) ?? keys.first(where: { $0["use"] == nil }) else {
            throw SubmissionError.noEncryptionKey
        }
        return key
    }

    private func selectAlgorithm(_ keyAlg: String?, _ metadata: [String: Any]) throws -> KeyManagementAlgorithm {
        let named = keyAlg.flatMap { $0.isEmpty ? nil : $0 }
            ?? (metadata[Self.draftAlg] as? String).flatMap { $0.isEmpty ? nil : $0 }
        guard let named else { return .ECDH_ES }
        guard let algorithm = KeyManagementAlgorithm(rawValue: named), Self.supportedAlgorithms.contains(algorithm) else {
            throw SubmissionError.encryptionUnsupported("the key algorithm \(named) is not supported")
        }
        return algorithm
    }

    private func selectEncryption(_ metadata: [String: Any]) throws -> ContentEncryptionAlgorithm {
        let supported: [String]
        if let values = metadata[Self.encValuesSupported] as? [String] {
            supported = values
        } else if let value = metadata[Self.draftEnc] as? String {
            supported = [value]
        } else if let values = metadata[Self.legacyEncValuesSupported] as? [String] {
            supported = values
        } else {
            supported = [ContentEncryptionAlgorithm.A128GCM.rawValue]
        }
        guard let chosen = Self.preference.first(where: { supported.contains($0.rawValue) }) else {
            throw SubmissionError.encryptionUnsupported("none of the content encryptions \(supported) is supported")
        }
        return chosen
    }
}
