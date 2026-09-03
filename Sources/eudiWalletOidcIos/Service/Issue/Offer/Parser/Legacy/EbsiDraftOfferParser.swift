//
//  EbsiDraftOfferParser.swift
//  eudiWalletOidcIos
//

import Foundation

/// LEGACY -- pre-1.0 draft, EBSI flavour: `credentials` is an array of **objects** carrying
/// `format`, `types`, `doctype` and `trust_framework`.
///
/// This is the only offer shape that conveys a format or an mdoc `doctype` in the offer itself, so
/// those fields are passed through untouched.
///
/// Delete this file and its registry entry to drop draft support.
struct EbsiDraftOfferParser: CredentialOfferParser {

    let specVersion: CredentialOfferSpecVersion = .draft

    private static let credentials = "credentials"

    func supports(_ json: [String: Any]) -> Bool {
        guard let credentials = json[Self.credentials] as? [Any], !credentials.isEmpty else {
            return false
        }
        // An empty array is ambiguous between the two draft flavours; let the EWC parser take it.
        return credentials.allSatisfy { $0 is [String: Any] }
    }

    func parse(_ data: Data) throws -> CredentialOffer {
        guard let model = try? JSONDecoder().decode(CredentialOfferResponse.self, from: data) else {
            throw CredentialOfferError.malformed("The credential offer could not be read")
        }
        return CredentialOffer(from: model)
    }
}
