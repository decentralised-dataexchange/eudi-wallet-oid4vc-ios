//
//  DraftIssuerMetadataParser.swift
//  eudiWalletOidcIos
//

import Foundation

/// LEGACY -- pre-1.0 draft Credential Issuer metadata.
///
/// Identified by `credentials_supported`, an **array** of credential objects rather than 1.0's
/// object keyed by configuration id. These documents also carry the singular `authorization_server`
/// in place of 1.0's `authorization_servers` array, and EBSI adds a `trust_framework` object that
/// appears in no version of the specification.
///
/// This is the shape the EBSI conformance issuer publishes, so deleting it drops EBSI support.
struct DraftIssuerMetadataParser: IssuerMetadataParser {

    let specVersion: IssuerMetadataSpecVersion = .draft

    private static let key = "credentials_supported"

    func supports(_ json: [String: Any]) -> Bool {
        json[Self.key] != nil && !(json[Self.key] is NSNull)
    }

    func parse(_ data: Data) throws -> IssuerWellKnownConfiguration {
        guard let model = try? JSONDecoder().decode(IssuerWellKnownConfigurationResponse.self, from: data) else {
            throw DiscoveryError.malformed("The issuer configuration could not be read")
        }
        return IssuerWellKnownConfiguration(from: model)
    }
}
