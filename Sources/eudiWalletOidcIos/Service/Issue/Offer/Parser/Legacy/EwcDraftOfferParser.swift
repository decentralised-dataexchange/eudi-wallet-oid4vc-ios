//
//  EwcDraftOfferParser.swift
//  eudiWalletOidcIos
//

import Foundation

/// LEGACY -- pre-1.0 draft, EWC flavour: `credentials` is an array of **strings**, each naming a
/// credential type.
///
/// Unlike the previous implementation this does not accept any document at all: one with no
/// `credentials` array is rejected rather than becoming an empty offer.
///
/// Delete this file and its registry entry to drop draft support.
struct EwcDraftOfferParser: CredentialOfferParser {

    let specVersion: CredentialOfferSpecVersion = .draft

    private static let credentials = "credentials"

    func supports(_ json: [String: Any]) -> Bool {
        guard let credentials = json[Self.credentials] as? [Any] else { return false }
        return credentials.allSatisfy { $0 is String }
    }

    func parse(_ data: Data) throws -> CredentialOffer {
        guard let model = try? JSONDecoder().decode(CredentialOfferResponse.self, from: data) else {
            throw CredentialOfferError.malformed("The credential offer could not be read")
        }
        return CredentialOffer(from: model)
    }
}
