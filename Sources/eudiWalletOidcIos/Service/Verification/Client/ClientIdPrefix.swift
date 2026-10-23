//
//  ClientIdPrefix.swift
//  eudiWalletOidcIos
//

import Foundation

/// OpenID4VP 1.0 section 5.9: the part of a `client_id` before the first colon, which says how
/// the verifier authenticates its request.
///
/// The legacy cases are the draft 20 "client id schemes" that 1.0 dropped or renamed; they live
/// here so a request from an older verifier still parses, and their handlers sit under `Legacy/`.
public enum ClientIdPrefix: CaseIterable {

    /// The identifier is the redirect or response URI. The request carries no authentication.
    case redirectUri

    /// The identifier is an OpenID Federation entity identifier. Not implemented.
    case openidFederation

    /// The identifier is a DID; the request is signed with a key from its DID document.
    case decentralizedIdentifier

    /// The request carries a verifier attestation JWT in its `jwt` header.
    case verifierAttestation

    /// The identifier is a dNSName SAN of the leaf certificate in the `x5c` header.
    case x509SanDns

    /// The identifier is the base64url SHA-256 of the leaf certificate in the `x5c` header.
    case x509Hash

    /// Reserved for the Digital Credentials API audience; section 5.9.3 says a request MUST NOT use it.
    case origin

    /// No prefix, or one this SDK does not recognise: section 5.9.2, a pre-registered client.
    case preRegistered

    // --- legacy, draft 20 and earlier ---
    case https
    case did
    case x509SanUri
    case webOrigin

    /// The text before the colon, or nil for a client id with no prefix.
    public var value: String? {
        switch self {
        case .redirectUri: return "redirect_uri"
        case .openidFederation: return "openid_federation"
        case .decentralizedIdentifier: return "decentralized_identifier"
        case .verifierAttestation: return "verifier_attestation"
        case .x509SanDns: return "x509_san_dns"
        case .x509Hash: return "x509_hash"
        case .origin: return "origin"
        case .preRegistered: return nil
        case .https: return "https"
        case .did: return "did"
        case .x509SanUri: return "x509_san_uri"
        case .webOrigin: return "web-origin"
        }
    }

    public var isLegacy: Bool {
        switch self {
        case .https, .did, .x509SanUri, .webOrigin: return true
        default: return false
        }
    }

    /// True for the draft schemes whose text is part of the identifier itself (`https://...`,
    /// `did:...`), so the whole client id is the identifier. The other legacy prefixes
    /// (`x509_san_uri:`, `web-origin:`) are stripped like the 1.0 ones.
    var keepsPrefixInIdentifier: Bool {
        self == .https || self == .did
    }

    static func from(_ value: String?) -> ClientIdPrefix? {
        guard let value else { return nil }
        return allCases.first { $0.value == value }
    }
}
