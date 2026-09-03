//
//  IssuerMetadataParser.swift
//  eudiWalletOidcIos
//

import Foundation

/// Turns a Credential Issuer metadata document into the normalised `IssuerWellKnownConfiguration`.
///
/// One implementation per spec revision, selected by document shape rather than by any version
/// field on the wire. Parsers are tried in registry order with OpenID4VCI 1.0 first, so a draft
/// parser only ever sees a document 1.0 has already declined.
protocol IssuerMetadataParser {

    /// Which revision this parser implements.
    var specVersion: IssuerMetadataSpecVersion { get }

    /// `true` when `json` is shaped like this revision's metadata.
    func supports(_ json: [String: Any]) -> Bool

    /// Normalises `data`. Only called when `supports(_:)` returned `true`.
    func parse(_ data: Data) throws -> IssuerWellKnownConfiguration
}
