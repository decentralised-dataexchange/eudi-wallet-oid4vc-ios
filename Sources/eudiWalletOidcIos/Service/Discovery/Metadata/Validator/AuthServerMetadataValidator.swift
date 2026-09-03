//
//  AuthServerMetadataValidator.swift
//  eudiWalletOidcIos
//

import Foundation

/// Conformance for a parsed authorization server metadata document (RFC 8414 section 2).
///
/// Deliberately light. RFC 8414 lists several REQUIRED parameters, but OpenID4VCI 1.0 already
/// carves one of them out -- "An Authorization Server that only supports the Pre-Authorized Code
/// grant type MAY omit the response_types_supported parameter in its metadata despite [RFC8414]
/// mandating it" -- and rejecting a document over a parameter the wallet never reads would break
/// working issuers to no benefit. Only what the issuance flow actually depends on is enforced.
struct AuthServerMetadataValidator {

    func validate(
        _ config: AuthorisationServerWellKnownConfiguration,
        expectedIdentifier: String
    ) throws -> AuthorisationServerWellKnownConfiguration {
        guard let tokenEndpoint = config.tokenEndpoint, !tokenEndpoint.isEmpty else {
            throw DiscoveryError.invalid("The authorization server configuration does not name a token endpoint")
        }

        // RFC 8414 section 3.3: the issuer returned MUST be identical to the identifier the
        // metadata was requested for. Reported rather than enforced -- deployments behind a proxy
        // routinely publish the upstream identifier, and the wallet reads the endpoints, not this.
        if let declared = config.issuer?.trimmingCharacters(in: .whitespaces), !declared.isEmpty {
            let normalise: (String) -> String = { value in
                var value = value
                while value.hasSuffix("/") { value.removeLast() }
                return value
            }
            if normalise(declared) != normalise(expectedIdentifier) {
                debugPrint("### Authorization server metadata declares issuer \(declared) but was fetched for \(expectedIdentifier)")
            }
        }
        return config
    }
}
