//
//  VerificationFixtures.swift
//  eudiWalletOidcIosTests
//

import Foundation
import CryptoKit
import SwiftCBOR
@testable import eudiWalletOidcIos

/// Shared inputs for the verification characterisation tests: holder keys, the three credential
/// shapes the builders accept, and the two request shapes (Presentation Exchange and DCQL).
enum VerificationFixtures {

    static let clientId = "x509_san_dns:verifier.example.com"
    static let nonce = "n-verifier-1"
    static let state = "s-1"
    static let responseUri = "https://verifier.example.com/response"
    static let did = "did:key:zTestHolder"
    static let vct = "urn:eudi:pid:1"
    static let docType = "org.iso.18013.5.1.mDL"

    /// A compact JWT whose signature is a placeholder; the builders only read the payload.
    static func unsignedJwt(_ claims: [String: Any]) -> String {
        let header = Data(#"{"alg":"ES256","kid":"issuer"}"#.utf8).b64url
        let payload = (try? JSONSerialization.data(withJSONObject: claims))?.b64url ?? ""
        return "\(header).\(payload).c2lnbmF0dXJl"
    }

    /// An SD-JWT with no disclosures: issuer JWT followed by the `~` separator.
    static func sdJwt(vct: String = vct) -> String {
        unsignedJwt(["vct": vct, "iss": "https://issuer.example", "given_name": "Alice"]) + "~"
    }

    /// A W3C VC as a plain JWT, no `vct`.
    static func jwtVc() -> String {
        unsignedJwt(["iss": "https://issuer.example", "vc": ["type": ["VerifiableCredential"]]])
    }

    /// A minimal IssuerSigned whose MSO names `docType` and binds `deviceKey`.
    static func mdoc(deviceKey: P256.Signing.PublicKey?, docType: String = docType,
                     nameSpaces: [String: [String: String]] = [:]) -> String {
        var mso: [(CBOR, CBOR)] = [(.utf8String("docType"), .utf8String(docType))]
        if let deviceKey {
            let raw = [UInt8](deviceKey.rawRepresentation)
            let coseKey: CBOR = .map([.unsignedInt(1): .unsignedInt(2), .negativeInt(0): .unsignedInt(1),
                                      .negativeInt(1): .byteString(Array(raw.prefix(32))),
                                      .negativeInt(2): .byteString(Array(raw.suffix(32)))])
            mso.append((.utf8String("deviceKeyInfo"), .map([.utf8String("deviceKey"): coseKey])))
        }
        let taggedMso: CBOR = .tagged(CBOR.Tag(rawValue: 24), .byteString(CBOR.map(.init(uniqueKeysWithValues: mso)).encode()))
        let issuerAuth: CBOR = .array([.byteString([0xA1, 0x01, 0x26]), .map([:]),
                                       .byteString(taggedMso.encode()), .byteString([UInt8](repeating: 0, count: 64))])
        let issuerNameSpaces: [(CBOR, CBOR)] = nameSpaces.sorted { $0.key < $1.key }.map { namespace, elements in
            let items: [CBOR] = elements.sorted { $0.key < $1.key }.enumerated().map { index, element in
                let item: CBOR = .map([.utf8String("digestID"): .unsignedInt(UInt64(index)),
                                       .utf8String("random"): .byteString([UInt8](repeating: UInt8(index), count: 16)),
                                       .utf8String("elementIdentifier"): .utf8String(element.key),
                                       .utf8String("elementValue"): .utf8String(element.value)])
                return .tagged(CBOR.Tag(rawValue: 24), .byteString(item.encode()))
            }
            return (.utf8String(namespace), .array(items))
        }
        let signed: CBOR = .map([.utf8String("nameSpaces"): .map(.init(uniqueKeysWithValues: issuerNameSpaces)),
                                 .utf8String("issuerAuth"): issuerAuth])
        return Data(signed.encode()).b64url
    }

    static func decodeCbor(_ base64Url: String) -> CBOR? {
        guard let data = Data(b64url: base64Url) else { return nil }
        return try? CBOR.decode([UInt8](data))
    }

    // MARK: Presentation Exchange

    static func sdJwtDescriptor(_ id: String = "pid") -> [String: Any] {
        ["id": id, "format": ["vc+sd-jwt": ["alg": ["ES256"]]]]
    }

    static func jwtDescriptor(_ id: String = "vc") -> [String: Any] {
        ["id": id, "format": ["jwt_vp": ["alg": ["ES256"]]]]
    }

    static func mdocDescriptor(_ id: String = "mdl") -> [String: Any] {
        ["id": id, "format": ["mso_mdoc": ["alg": ["ES256"]]]]
    }

    static func pexRequest(_ descriptors: [String: Any]..., responseType: String? = "vp_token",
                           responseMode: String? = "direct_post", transactionData: [String] = [],
                           clientMetadata: [String: Any]? = nil) -> PresentationRequest {
        let definition: [String: Any] = ["id": "pd-1", "input_descriptors": descriptors]
        return request(responseType: responseType, responseMode: responseMode, transactionData: transactionData,
                       clientMetadata: clientMetadata, presentationDefinition: json(definition))
    }

    // MARK: DCQL

    static func dcqlSdJwt(_ id: String = "pid", vct: String = vct) -> CredentialItems {
        CredentialItems(id: id, format: "dc+sd-jwt", meta: .dcSDJWT(DCSDJWTMeta(vctValues: [vct])), claims: [],
                        multiple: nil, claimSets: nil)
    }

    static func dcqlMdoc(_ id: String = "mdl", docType: String = docType, claims: [Claim] = []) -> CredentialItems {
        CredentialItems(id: id, format: "mso_mdoc", meta: .msoMdoc(MSOMdocMeta(doctypeValue: docType)), claims: claims,
                        multiple: nil, claimSets: nil)
    }

    static func dcqlJwt(_ id: String = "vc") -> CredentialItems {
        CredentialItems(id: id, format: "jwt_vc_json", meta: .jwt(JWTMeta(typeValues: [["VerifiableCredential"]])),
                        claims: [], multiple: nil, claimSets: nil)
    }

    static func dcqlRequest(_ entries: CredentialItems..., responseType: String? = "vp_token",
                            responseMode: String? = "direct_post", transactionData: [String] = [],
                            clientMetadata: [String: Any]? = nil) -> PresentationRequest {
        var request = request(responseType: responseType, responseMode: responseMode, transactionData: transactionData,
                              clientMetadata: clientMetadata, presentationDefinition: nil)
        request.dcqlQuery = DCQLQuery(credentials: entries)
        return request
    }

    private static func request(responseType: String?, responseMode: String?, transactionData: [String],
                                clientMetadata: [String: Any]?, presentationDefinition: String?) -> PresentationRequest {
        PresentationRequest(state: state, clientId: clientId, redirectUri: nil, responseUri: responseUri,
                            responseType: responseType, responseMode: responseMode, scope: nil, nonce: nonce,
                            requestUri: nil, presentationDefinition: presentationDefinition,
                            clientMetaData: clientMetadata.map(json), presentationDefinitionUri: nil,
                            clientMetaDataUri: nil, clientIDScheme: "x509_san_dns", transactionData: transactionData,
                            request: nil, authSession: nil)
    }

    // MARK: Transaction data and client metadata

    /// One `transaction_data` entry: base64url JSON naming `type` and the credential ids it binds to.
    static func transactionData(_ type: String, _ credentialIds: String...) -> String {
        Data(json(["type": type, "credential_ids": credentialIds]).utf8).b64url
    }

    /// Client metadata with an embedded JWKS holding the verifier's encryption key.
    static func encryptionMetadata(_ key: VerifierKey, encValues: [String]? = ["A128GCM"], enc: String? = nil,
                                   alg: String? = nil, version: String? = nil) -> [String: Any] {
        var metadata: [String: Any] = ["jwks": ["keys": [key.publicJwk]]]
        encValues.map { metadata["encrypted_response_enc_values_supported"] = $0 }
        enc.map { metadata["authorization_encrypted_response_enc"] = $0 }
        alg.map { metadata["authorization_encrypted_response_alg"] = $0 }
        version.map { metadata["version"] = $0 }
        return metadata
    }

    // MARK: Reading results

    static func json(_ object: Any) -> String {
        String(data: (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data(),
               encoding: .utf8) ?? ""
    }

    static func object(_ text: Any?) -> Any? {
        guard let text = text as? String, let data = text.data(using: .utf8) else { return nil }
        return try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    }

    /// The key binding JWT appended after the last `~` of a presented SD-JWT.
    static func keyBindingJwt(_ presented: String) -> String {
        String(presented[presented.index(after: presented.lastIndex(of: "~") ?? presented.startIndex)...])
    }

    /// Whether `jwt` carries a valid ES256 signature by `key`.
    static func verifies(_ jwt: String, with key: P256.Signing.PublicKey) -> Bool {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let raw = Data(b64url: String(parts[2])),
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
        return key.isValidSignature(signature, for: Data("\(parts[0]).\(parts[1])".utf8))
    }

    static func sha256(_ text: String) -> String {
        Data(SHA256.hash(data: Data(text.utf8))).b64url
    }
}

/// A software P-256 key standing in for a Secure Enclave key: it reports the public key the same
/// way (X9.63) and signs the same way (compact ES256), so the builders cannot tell the difference.
final class SoftwareKey: NSObject, SecureKeyProtocol {
    var keyStorageType: SecureKeyTypes = .secureEnclave
    let privateKey = P256.Signing.PrivateKey()
    var publicKey: P256.Signing.PublicKey { privateKey.publicKey }

    func generateSecureKey() -> SecureKeyData? {
        SecureKeyData(publicKey: privateKey.publicKey.x963Representation, privateKey: nil)
    }

    func sign(payload: String, header: Data, withKey privateKey: Data?) -> String? {
        let input = "\(header.b64url).\(Data(payload.utf8).b64url)"
        guard let signature = try? self.privateKey.signature(for: Data(input.utf8)) else { return nil }
        return "\(input).\(signature.rawRepresentation.b64url)"
    }

    func getSecurePrivateKey() -> SecKey? {
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                         kSecAttrKeySizeInBits as String: 256]
        return SecKeyCreateWithData(privateKey.x963Representation as CFData, attributes as CFDictionary, nil)
    }
}

/// A key that cannot sign: what a missing or broken stored key looks like to the builders.
final class UnusableKey: NSObject, SecureKeyProtocol {
    var keyStorageType: SecureKeyTypes = .secureEnclave
    func generateSecureKey() -> SecureKeyData? { nil }
    func sign(payload: String, header: Data, withKey privateKey: Data?) -> String? { nil }
}

extension Data {
    /// Base64url without padding. Spelt out here because the SDK and JOSESwift both declare
    /// `base64URLEncodedString()`, which is ambiguous in a file that sees both.
    var b64url: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(b64url text: String) {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }
}
