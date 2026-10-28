//
//  RequestObjectCertificates.swift
//  eudiWalletOidcIos
//

import Foundation
import Security
import CryptoKit
import ASN1Decoder

/// The X.509 side of the `x509_*` prefixes: the `x5c` header, the leaf key, the chain. Also the
/// JWS helpers the other prefixes share.
enum RequestObjectCertificates {

    static func header(_ jwt: String) -> [String: Any]? { segment(jwt, 0) }

    static func claims(_ jwt: String) -> [String: Any]? { segment(jwt, 1) }

    /// The `x5c` chain, leaf first, or nil when the header has none.
    static func chain(_ jwt: String) throws -> [SecCertificate]? {
        guard let encoded = header(jwt)?["x5c"] as? [String], !encoded.isEmpty else { return nil }
        return try encoded.map { item in
            guard let der = Data(base64Encoded: item), let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
                throw PresentationRequestError.clientNotVerified("the x5c certificate chain could not be read")
            }
            return certificate
        }
    }

    static func verifySignature(_ jwt: String, certificate: SecCertificate) -> Bool {
        let der = SecCertificateCopyData(certificate) as Data
        return X509SanRequestVerifier.shared.validateSignatureWithCertificate(jwt: jwt, x5cChain: [der.base64EncodedString()])
    }

    static func verifySignature(_ jwt: String, jwk: [String: Any]) -> Bool {
        SignatureValidator.validateSignature(jwt: jwt, jwk: [jwk]).0 == true
    }

    /// Section 5.9.3: "The Wallet MUST validate the signature and the trust chain of the X.509
    /// certificate." Every certificate must be within its validity period and signed by the next
    /// one in the chain. When `anchors` are given the chain must also end in one of them, and the
    /// result is true. Without anchors the chain is only checked for consistency and the result
    /// is false: the trust decision then rests with the host.
    static func checkChain(_ chain: [SecCertificate], anchors: [SecCertificate]) throws -> Bool {
        for certificate in chain {
            guard let parsed = try? X509Certificate(der: SecCertificateCopyData(certificate) as Data),
                  parsed.checkValidity() else {
                throw PresentationRequestError.clientNotVerified("a certificate in the x5c chain is expired or not yet valid")
            }
        }
        if chain.count > 1, let top = chain.last, !evaluate(chain, anchors: [top]) {
            throw PresentationRequestError.clientNotVerified("the x5c certificate chain does not link")
        }
        if anchors.isEmpty { return false }

        // The anchor itself must not be part of the path handed to the evaluation.
        let anchorData = anchors.map { SecCertificateCopyData($0) as Data }
        let path = chain.filter { !anchorData.contains(SecCertificateCopyData($0) as Data) }
        if path.isEmpty { return true }
        guard evaluate(path, anchors: anchors) else {
            throw PresentationRequestError.clientNotVerified("the x5c certificate chain does not end in a trusted anchor")
        }
        return true
    }

    /// RFC 5280 dNSName entries (GeneralName tag 2).
    static func dnsNames(_ certificate: SecCertificate) -> [String] { sanOfType(certificate, 2) }

    /// RFC 5280 uniformResourceIdentifier entries (GeneralName tag 6).
    static func uriNames(_ certificate: SecCertificate) -> [String] { sanOfType(certificate, 6) }

    /// Section 5.9.3 `x509_hash`: "the base64url-encoded value of the SHA-256 hash of the DER-encoded X.509 certificate".
    static func sha256Base64Url(_ certificate: SecCertificate) -> String {
        Data(SHA256.hash(data: SecCertificateCopyData(certificate) as Data)).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Evaluates `path` against `anchors` only, offline, with no revocation check.
    private static func evaluate(_ path: [SecCertificate], anchors: [SecCertificate]) -> Bool {
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(path as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust else { return false }
        SecTrustSetAnchorCertificates(trust, anchors as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        SecTrustSetNetworkFetchAllowed(trust, false)
        return SecTrustEvaluateWithError(trust, nil)
    }

    private static func sanOfType(_ certificate: SecCertificate, _ tag: UInt8) -> [String] {
        guard let blocks = try? ASN1DERDecoder.decode(data: SecCertificateCopyData(certificate) as Data) else { return [] }
        // ASN1Object.parent is weak: without this, an optimised build frees the tree after the
        // OID lookup and the parent is nil.
        return withExtendedLifetime(blocks) {
            guard let oid = blocks.lazy.compactMap({ $0.findOid(.subjectAltName) }).first,
                  let ext = oid.parent else { return [] }
            // Extension ::= SEQUENCE { extnID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }, and
            // the OCTET STRING wraps the SEQUENCE OF GeneralName.
            guard let octets = children(ext).last(where: { $0.identifier?.tagNumber() == .octetString }),
                  let names = children(octets).first(where: { $0.identifier?.tagNumber() == .sequence }) else { return [] }
            return children(names).compactMap { name in
                guard name.identifier?.typeClass() == .contextSpecific,
                      name.identifier?.tagNumber().rawValue == tag else { return nil }
                return name.value as? String
            }
        }
    }

    private static func children(_ object: ASN1Object) -> [ASN1Object] {
        (0..<object.subCount()).compactMap { object.sub($0) }
    }

    private static func segment(_ jwt: String, _ index: Int) -> [String: Any]? {
        let parts = jwt.components(separatedBy: ".")
        guard parts.count == 3, let data = Data(base64URLEncoded: parts[index]) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}
