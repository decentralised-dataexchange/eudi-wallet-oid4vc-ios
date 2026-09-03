//
//  CredentialOfferPolicy.swift
//  eudiWalletOidcIos
//

import Foundation

/// What the SDK will accept when resolving a credential offer.
///
/// Kept in one place so a rule can be tightened or relaxed without touching the resolution logic.
/// ``standard`` preserves the SDK's existing, permissive behaviour; ``strict`` is what
/// OpenID4VCI 1.0 actually requires.
public struct CredentialOfferPolicy {

    /// Schemes accepted for the `credential_offer_uri` fetch.
    ///
    /// The specification requires `https`. `http` is kept by default because issuers are commonly
    /// run locally during development. This also closes `file:` and `ftp:`, which the previous
    /// implementation accepted because it performed no check at all.
    public var allowedURISchemes: Set<String>

    /// Reject a fetched offer whose `Content-Type` is not JSON.
    public var requireJSONContentType: Bool

    /// Largest offer document accepted, in bytes.
    public var maxOfferBytes: Int

    /// Reject an offer carrying both `credential_offer` and `credential_offer_uri`.
    /// Section 4.1 says they MUST NOT both be present.
    public var rejectAmbiguousOffers: Bool

    /// Accept pre-1.0 draft offers. Set `false` to require OpenID4VCI 1.0.
    public var allowDraftOffers: Bool

    public init(
        allowedURISchemes: Set<String> = ["https", "http"],
        requireJSONContentType: Bool = false,
        maxOfferBytes: Int = 256 * 1024,
        rejectAmbiguousOffers: Bool = true,
        allowDraftOffers: Bool = true
    ) {
        self.allowedURISchemes = allowedURISchemes
        self.requireJSONContentType = requireJSONContentType
        self.maxOfferBytes = maxOfferBytes
        self.rejectAmbiguousOffers = rejectAmbiguousOffers
        self.allowDraftOffers = allowDraftOffers
    }

    func allows(scheme: String?) -> Bool {
        guard let scheme else { return false }
        return allowedURISchemes.contains { $0.caseInsensitiveCompare(scheme) == .orderedSame }
    }

    /// The SDK's existing behaviour.
    public static let standard = CredentialOfferPolicy()

    /// OpenID4VCI 1.0 as written: https only, JSON enforced, no drafts.
    public static let strict = CredentialOfferPolicy(
        allowedURISchemes: ["https"],
        requireJSONContentType: true,
        allowDraftOffers: false
    )
}
