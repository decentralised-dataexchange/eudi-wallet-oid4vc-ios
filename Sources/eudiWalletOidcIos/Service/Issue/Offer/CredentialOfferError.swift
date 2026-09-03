//
//  CredentialOfferError.swift
//  eudiWalletOidcIos
//

import Foundation

/// Why a credential offer could not be resolved.
///
/// Every case carries a description meant to be shown to a user: the resolver puts it into
/// `CredentialOffer.error`, which hosts surface directly.
public enum CredentialOfferError: Error, LocalizedError, Equatable {

    /// The scanned data carried neither `credential_offer` nor `credential_offer_uri`.
    case noOffer

    /// Both transfer mechanisms present. OpenID4VCI 1.0 section 4.1 forbids this.
    case ambiguousOffer

    /// `credential_offer_uri` used a scheme the policy does not allow.
    case unsupportedScheme(String?)

    /// The `credential_offer_uri` fetch failed.
    case fetchFailed(status: Int?, detail: String?)

    /// The issuer returned something that is not JSON.
    case notJSON(contentType: String?)

    /// Section 4.1.3: "The Credential Offer cannot be signed and MUST NOT use application/jwt
    /// with `alg`: `none`."
    case signedOfferRejected

    /// The document exceeded `CredentialOfferPolicy.maxOfferBytes`.
    case tooLarge(bytes: Int)

    /// Not parseable JSON, or matched no known offer shape.
    case malformed(String)

    /// Parsed, but does not satisfy the specification.
    case invalid(String)

    public var errorDescription: String? {
        switch self {
        case .noOffer:
            return "This QR code does not contain a credential offer"
        case .ambiguousOffer:
            return "The credential offer is invalid: it uses both credential_offer and credential_offer_uri"
        case .unsupportedScheme(let scheme):
            return "The credential offer link uses an unsupported scheme: \(scheme ?? "none")"
        case .fetchFailed(let status, let detail):
            if let detail, !detail.isEmpty { return detail }
            if let status { return "The credential offer could not be downloaded (HTTP \(status))" }
            return "The credential offer could not be downloaded"
        case .notJSON:
            return "The credential offer was not in the expected format"
        case .signedOfferRejected:
            return "Signed credential offers are not supported"
        case .tooLarge:
            return "The credential offer is too large to process"
        case .malformed(let detail), .invalid(let detail):
            return detail
        }
    }

    /// HTTP status, when the failure came from a response.
    var httpStatus: Int? {
        if case .fetchFailed(let status, _) = self { return status }
        return nil
    }
}
