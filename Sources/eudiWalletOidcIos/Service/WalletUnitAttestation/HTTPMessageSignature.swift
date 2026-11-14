//
//  HTTPMessageSignature.swift
//  eudiWalletOidcIos
//
//  The HTTP message signature of a wallet provider protocol 2 request:
//  RFC 9421 with the label `wp` and the algorithm `ecdsa-p256-sha256`, over a
//  body bound by an RFC 9530 Content-Digest.
//

import Foundation
import CryptoKit

/// Pure functions that build the `Content-Digest`, `Signature-Input` and
/// `Signature` headers of a wallet provider request. The wallet provider
/// rebuilds the signature base from the request it receives and verifies it
/// with the request key of the wallet unit, so every byte here is wire
/// contract: the order of the components, the quoting, the LF line ends.
enum HTTPMessageSignature {

    static let label = "wp"
    static let algorithm = "ecdsa-p256-sha256"

    /// `sha-256=:<standard base64 with padding of SHA-256(body)>:` (RFC 9530).
    /// The body must be the exact bytes that go on the wire.
    static func contentDigest(body: Data) -> String {
        "sha-256=:" + Data(SHA256.hash(data: body)).base64EncodedString() + ":"
    }

    /// The signature parameters, the text after `wp=` in `Signature-Input`:
    ///
    ///     ("@method" "@target-uri" ...);created=<s>;keyid="<thumbprint>";alg="ecdsa-p256-sha256"
    static func signatureParams(components: [String], created: Int, keyId: String) -> String {
        "(" + components.map { "\"\($0)\"" }.joined(separator: " ") + ")"
            + ";created=\(created);keyid=\"\(keyId)\";alg=\"\(algorithm)\""
    }

    /// The signature base (RFC 9421 section 2.5): one line `"<component>": <value>`
    /// for each covered component, in order, then the `"@signature-params"`
    /// line. LF line ends, no LF at the end.
    ///
    /// `@method` and `@target-uri` come from the arguments; every other
    /// component is a header of `headers`, looked up without regard to case and
    /// trimmed (RFC 9421 section 2.1). Returns nil when a covered header is
    /// missing: such a request cannot be signed.
    static func signatureBase(
        method: String,
        targetURI: String,
        headers: [String: String],
        components: [String],
        signatureParams: String
    ) -> String? {
        let byName = Dictionary(headers.map { ($0.key.lowercased(), $0.value) },
                                uniquingKeysWith: { first, _ in first })
        var lines: [String] = []
        for component in components {
            let value: String
            switch component {
            case "@method":
                value = method.uppercased()
            case "@target-uri":
                value = targetURI
            default:
                guard let header = byName[component] else { return nil }
                value = header.trimmingCharacters(in: .whitespaces)
            }
            lines.append("\"\(component)\": \(value)")
        }
        lines.append("\"@signature-params\": \(signatureParams)")
        return lines.joined(separator: "\n")
    }

    /// The signed headers of a request.
    struct Signed {
        let signatureInput: String
        let signature: String
        /// For tests and diagnostics only; never log it in a release build.
        let signatureBase: String
    }

    /// Signs a request with `key`. `headers` must already hold every covered
    /// header with the value that goes on the wire. Returns nil when a covered
    /// header is missing or the key has no thumbprint; throws when the key
    /// refuses to sign.
    static func sign(
        method: String,
        targetURI: String,
        headers: [String: String],
        components: [String],
        created: Int,
        key: RequestSigningKey
    ) throws -> Signed? {
        guard let keyId = key.keyId else { return nil }
        let params = signatureParams(components: components, created: created, keyId: keyId)
        guard let base = signatureBase(method: method, targetURI: targetURI, headers: headers,
                                       components: components, signatureParams: params) else { return nil }
        let raw = try key.signRaw(Data(base.utf8))
        return Signed(
            signatureInput: "\(label)=\(params)",
            signature: "\(label)=:\(raw.base64EncodedString()):",
            signatureBase: base
        )
    }
}
