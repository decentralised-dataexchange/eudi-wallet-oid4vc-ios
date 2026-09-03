//
//  DiscoveryError.swift
//  eudiWalletOidcIos
//

import Foundation

/// Why metadata could not be discovered.
///
/// Every case carries a description meant to be shown to a user: the resolvers put it into the
/// configuration's `error`, which hosts surface directly.
public enum DiscoveryError: Error, LocalizedError, Equatable {

    /// No usable issuer or authorization server identifier was supplied.
    case noIdentifier

    /// The identifier used a scheme the policy does not allow.
    case unsupportedScheme(String?)

    /// The identifier was not a usable absolute URL.
    case invalidIdentifier(String?)

    /// The metadata request failed.
    case fetchFailed(status: Int?, detail: String?)

    /// The response was not the expected media type.
    case notJSON(contentType: String?)

    /// The document exceeded `DiscoveryPolicy.maxMetadataBytes`.
    case tooLarge(bytes: Int)

    /// Signed metadata was returned but could not be trusted.
    ///
    /// OpenID4VCI 1.0 section 12.2.3: "When requesting signed metadata, the Wallet MUST establish
    /// trust in the signer of the metadata. Otherwise, the Wallet MUST reject the signed metadata."
    case signedMetadataRejected(String)

    /// Not parseable JSON, or matched no known metadata shape.
    case malformed(String)

    /// Parsed, but does not satisfy the specification.
    case invalid(String)

    public var errorDescription: String? {
        switch self {
        case .noIdentifier:
            return "No issuer address was supplied"
        case .unsupportedScheme(let scheme):
            return "The issuer address uses an unsupported scheme: \(scheme ?? "none")"
        case .invalidIdentifier(let identifier):
            return "The issuer address is not valid: \(identifier ?? "")"
        case .fetchFailed(let status, let detail):
            if let detail, !detail.isEmpty { return detail }
            if let status { return "The issuer configuration could not be downloaded (HTTP \(status))" }
            return "The issuer configuration could not be downloaded"
        case .notJSON:
            return "The issuer configuration was not in the expected format"
        case .tooLarge:
            return "The issuer configuration is too large to process"
        case .signedMetadataRejected(let detail), .malformed(let detail), .invalid(let detail):
            return detail
        }
    }

    /// HTTP status, when the failure came from a response.
    var httpStatus: Int? {
        if case .fetchFailed(let status, _) = self { return status }
        return nil
    }

    /// Which of two failures to report when several well-known URLs were tried.
    ///
    /// A failure that got as far as reading a document says more than one that never found a
    /// document, and a definite HTTP error says more than a 404 -- a 404 usually just means "this
    /// issuer uses the other URL form". Ties keep the earlier failure, so the spec URL's complaint
    /// wins over the fallback's.
    static func mostInformative(_ current: DiscoveryError?, _ other: DiscoveryError) -> DiscoveryError {
        guard let current else { return other }
        return other.informativeness > current.informativeness ? other : current
    }

    private var informativeness: Int {
        if case .fetchFailed(let status, _) = self { return status == 404 ? 1 : 2 }
        return 3
    }
}
