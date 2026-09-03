//
//  OpenId4VciV1OfferParser.swift
//  eudiWalletOidcIos
//

import Foundation

/// OpenID4VCI 1.0 -- the revision this SDK targets.
///
/// Recognised by `credential_configuration_ids`, which 1.0 makes REQUIRED and which no draft
/// revision uses. That single key is the whole discriminator, so detection does not depend on
/// anything else in the document.
struct OpenId4VciV1OfferParser: CredentialOfferParser {

    let specVersion: CredentialOfferSpecVersion = .v1_0

    private static let configurationIDs = "credential_configuration_ids"

    func supports(_ json: [String: Any]) -> Bool {
        json[Self.configurationIDs] is [Any]
    }

    func parse(_ data: Data) throws -> CredentialOffer {
        guard let model = try? JSONDecoder().decode(CredentialOfferV2.self, from: data) else {
            throw CredentialOfferError.malformed("The credential offer could not be read")
        }
        return CredentialOffer(from: model)
    }
}
