//
//  CredentialOfferParser.swift
//  eudiWalletOidcIos
//

import Foundation

/// Turns an offer document into the normalised `CredentialOffer`.
///
/// One implementation per spec revision. Parsers are tried in registry order with OpenID4VCI 1.0
/// first, so a draft parser only ever sees a document 1.0 has already declined.
///
/// Implementations must be pure: `supports(_:)` decides on shape alone and neither method performs
/// I/O.
protocol CredentialOfferParser {

    /// Which revision this parser implements.
    var specVersion: CredentialOfferSpecVersion { get }

    /// `true` when `json` is shaped like this revision's offer.
    func supports(_ json: [String: Any]) -> Bool

    /// Normalises `data`. Only called when `supports(_:)` returned `true`.
    func parse(_ data: Data) throws -> CredentialOffer
}
