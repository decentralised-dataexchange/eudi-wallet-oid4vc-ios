//
//  SignedMetadataVerifier.swift
//  eudiWalletOidcIos
//

import Foundation

/// Who signed a metadata document, as far as the signature itself can say.
///
/// Everything here is **self-asserted by the document**. Verifying the signature proves it was
/// signed by the key named below; it says nothing about whether that key may speak for the issuer.
/// That judgement is ``MetadataSignerTrust``'s.
public struct SignedMetadataSigner {
    /// The Credential Issuer Identifier the document claims to describe (`sub`).
    public let issuerIdentifier: String
    /// The JOSE `kid`, often a DID.
    public let keyID: String?
    /// The JOSE `x5c` chain, leaf first, base64 as received.
    public let x5c: [String]?
    /// The `iss` claim, when the signer is not the issuer itself.
    public let issuedBy: String?
}

/// Decides whether a verified signer may publish metadata for an issuer.
///
/// This is the "establish trust" half of OpenID4VCI 1.0 section 12.2.3, and the SDK cannot supply
/// it: the specification puts the mechanism out of scope precisely because it is
/// deployment-specific. A host backs this with whatever it already trusts.
public protocol MetadataSignerTrust {
    func isTrusted(_ signer: SignedMetadataSigner) async -> Bool
}

/// Accept any signer whose signature verified. **This is not a trust decision.**
///
/// The current default, and a deliberate, temporary step: it gets signed metadata working and
/// closes the far worse hole it replaces, where a JWT payload was decoded and used with no
/// signature check at all. What it still does not do is establish that the verified key may speak
/// for the issuer.
///
/// **Next iteration:** replace with a lookup against the trust list services in
/// `Service/TrustService`.
public struct SignatureOnlyMetadataSignerTrust: MetadataSignerTrust {
    public init() {}
    public func isTrusted(_ signer: SignedMetadataSigner) async -> Bool {
        debugPrint("### Accepting signed metadata for \(signer.issuerIdentifier) on signature alone; the signer is not checked against any trust list")
        return true
    }
}

/// Establishes trust in signed Credential Issuer Metadata.
///
/// Section 12.2.3 allows an issuer to return its metadata as a JWT with media type
/// `application/jwt`, and is unambiguous about the obligation that comes with reading one:
///
/// > When requesting signed metadata, the Wallet MUST establish trust in the signer of the
/// > metadata. Otherwise, the Wallet MUST reject the signed metadata.
public protocol SignedMetadataVerifier {

    /// Whether the wallet can verify signed metadata. Drives the `Accept` header.
    var supportsSignedMetadata: Bool { get }

    /// - Returns: the verified JWS payload as JSON.
    /// - Throws: ``DiscoveryError/signedMetadataRejected(_:)`` when trust cannot be established.
    func verify(jwt: String, expectedIssuerIdentifier: String) async throws -> Data
}

/// The default: refuse signed metadata rather than read it unverified.
///
/// Before this existed the SDK split the document on `.`, base64-decoded the middle segment and
/// used it as configuration -- no signature check, no `typ`, no `alg` -- so anyone able to serve
/// the metadata response could choose the `credential_endpoint` the wallet then posted credential
/// requests to.
public struct RejectingSignedMetadataVerifier: SignedMetadataVerifier {
    public init() {}
    public let supportsSignedMetadata = false

    public func verify(jwt: String, expectedIssuerIdentifier: String) async throws -> Data {
        throw DiscoveryError.signedMetadataRejected(
            "This issuer returned signed configuration, which this wallet cannot verify"
        )
    }
}

/// Verifies signed metadata using the SDK's existing `SignatureValidator`, adding everything
/// section 12.2.3 requires on top of a valid signature:
///
/// - `typ` MUST be `openidvci-issuer-metadata+jwt`;
/// - `alg` MUST NOT be `none` or a symmetric (MAC) algorithm;
/// - `sub` is REQUIRED and MUST equal the identifier the document was fetched for;
/// - `iat` is REQUIRED, and `exp`, when present, must not have passed.
///
/// The signature is checked **before any claim is read**: claims from a document whose signature
/// has not been established are attacker-controlled, so nothing is decided on them.
public struct SignatureValidatorSignedMetadataVerifier: SignedMetadataVerifier {

    public let supportsSignedMetadata = true

    private let trust: MetadataSignerTrust
    private let clockSkew: TimeInterval

    public init(trust: MetadataSignerTrust = SignatureOnlyMetadataSignerTrust(), clockSkew: TimeInterval = 60) {
        self.trust = trust
        self.clockSkew = clockSkew
    }

    private static let type = "openidvci-issuer-metadata+jwt"

    public func verify(jwt: String, expectedIssuerIdentifier: String) async throws -> Data {
        let segments = jwt.components(separatedBy: ".")
        guard segments.count == 3, !segments[2].isEmpty else {
            throw DiscoveryError.signedMetadataRejected("Its signed configuration is unsigned")
        }
        guard let header = Self.json(segments[0]), let payloadJSON = Self.json(segments[1]),
              let payload = Self.data(segments[1])
        else {
            throw DiscoveryError.signedMetadataRejected("Its signed configuration could not be read")
        }

        // Header first: `typ` and `alg` decide whether this is a document worth checking at all,
        // and both are covered by the signature, so a mismatch here is not a shortcut.
        guard (header["typ"] as? String)?.lowercased() == Self.type else {
            throw DiscoveryError.signedMetadataRejected("Its signed configuration is not typed as issuer metadata")
        }
        let algorithm = (header["alg"] as? String) ?? ""
        guard !algorithm.isEmpty, algorithm.lowercased() != "none", !algorithm.hasPrefix("HS") else {
            throw DiscoveryError.signedMetadataRejected("Its signed configuration uses an unacceptable signing algorithm")
        }

        let verified = (try? await SignatureValidator.validateSign(jwt: jwt, jwksURI: nil, format: "jwt")) ?? false
        guard verified == true else {
            throw DiscoveryError.signedMetadataRejected("Its signed configuration has an invalid signature")
        }

        guard let subject = payloadJSON["sub"] as? String, !subject.isEmpty else {
            throw DiscoveryError.signedMetadataRejected("Its signed configuration does not name an issuer")
        }
        guard subject == expectedIssuerIdentifier else {
            throw DiscoveryError.signedMetadataRejected("Its signed configuration belongs to a different issuer (\(subject))")
        }
        guard payloadJSON["iat"] != nil else {
            throw DiscoveryError.signedMetadataRejected("Its signed configuration is not dated")
        }
        if let expiry = payloadJSON["exp"] as? TimeInterval,
           Date() > Date(timeIntervalSince1970: expiry).addingTimeInterval(clockSkew) {
            throw DiscoveryError.signedMetadataRejected("Its signed configuration has expired")
        }

        let signer = SignedMetadataSigner(
            issuerIdentifier: subject,
            keyID: header["kid"] as? String,
            x5c: header["x5c"] as? [String],
            issuedBy: payloadJSON["iss"] as? String
        )
        guard await trust.isTrusted(signer) else {
            throw DiscoveryError.signedMetadataRejected(
                "Its signed configuration is signed by a party this wallet does not trust"
            )
        }
        return payload
    }

    private static func data(_ segment: String) -> Data? {
        guard let decoded = segment.decodeBase64() else { return nil }
        return decoded.data(using: .utf8)
    }

    private static func json(_ segment: String) -> [String: Any]? {
        guard let data = data(segment) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}
