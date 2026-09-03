//
//  InlineCredentialOfferSource.swift
//  eudiWalletOidcIos
//

import Foundation

/// The offer travels inside the link itself, as `?credential_offer=<url-encoded JSON>`.
///
/// OpenID4VCI 1.0 section 4.1.2.
struct InlineCredentialOfferSource: CredentialOfferSource {

    let name = "credential_offer"

    private static let parameter = "credential_offer"

    func supports(_ data: String) -> Bool {
        let value = OfferURI.queryParameter(Self.parameter, in: data)
        return !(value ?? "").isEmpty
    }

    func retrieve(_ data: String, policy: CredentialOfferPolicy) async throws -> Data {
        guard let offer = OfferURI.queryParameter(Self.parameter, in: data), !offer.isEmpty else {
            throw CredentialOfferError.noOffer
        }
        guard offer.utf8.count <= policy.maxOfferBytes else {
            throw CredentialOfferError.tooLarge(bytes: offer.utf8.count)
        }
        return Data(offer.utf8)
    }
}
