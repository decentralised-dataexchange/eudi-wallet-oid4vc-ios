//
//  OpenId4VciV1IssuerMetadataParser.swift
//  eudiWalletOidcIos
//

import Foundation

/// OpenID4VCI 1.0 Credential Issuer metadata.
///
/// Identified by `credential_configurations_supported`, which 1.0 defines as an object keyed by
/// configuration id. Drafts carried `credentials_supported` instead, so the two shapes never
/// collide and this parser can be tried first without risk.
struct OpenId4VciV1IssuerMetadataParser: IssuerMetadataParser {

    let specVersion: IssuerMetadataSpecVersion = .v1_0

    private static let key = "credential_configurations_supported"

    func supports(_ json: [String: Any]) -> Bool {
        json[Self.key] != nil && !(json[Self.key] is NSNull)
    }

    func parse(_ data: Data) throws -> IssuerWellKnownConfiguration {
        guard let model = try? JSONDecoder().decode(IssuerWellKnownConfigurationResponseV2.self, from: data) else {
            throw DiscoveryError.malformed("The issuer configuration could not be read")
        }
        return IssuerWellKnownConfiguration(from: model)
    }
}
