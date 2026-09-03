//
//  IssuerMetadataValidator.swift
//  eudiWalletOidcIos
//

import Foundation

/// Spec conformance for parsed Credential Issuer metadata, in one place.
///
/// **Version-aware on purpose.** Applying 1.0's REQUIRED rules to a draft document would reject
/// every pre-1.0 issuer, EBSI included, so a rule only fails a document of the revision that
/// actually defines it. Rules that protect the wallet rather than enforce a spec formality apply
/// to both.
struct IssuerMetadataValidator {

    /// - Parameter expectedIdentifier: the Credential Issuer Identifier the document was fetched for.
    func validate(
        _ config: IssuerWellKnownConfiguration,
        specVersion: IssuerMetadataSpecVersion,
        expectedIdentifier: String,
        policy: DiscoveryPolicy
    ) throws -> IssuerWellKnownConfiguration {
        try validateIssuerIdentity(config, specVersion: specVersion,
                                   expectedIdentifier: expectedIdentifier, policy: policy)
        try validateEndpoints(config, specVersion: specVersion, policy: policy)
        return config
    }

    /// Section 12.2.4: `credential_issuer` is REQUIRED and "MUST be identical to the Credential
    /// Issuer's identifier value into which the well-known URI string was inserted"; if they differ
    /// "the data contained in the response MUST NOT be used".
    ///
    /// Compared ignoring a trailing slash: the specification's "no normalization" forbids
    /// canonicalising the URL -- case, percent-encoding, default ports -- because those change which
    /// host or path is addressed. A trailing slash cannot, and this SDK strips one itself when
    /// deriving the identifier, so an exact comparison would reject an issuer for a normalisation
    /// we performed.
    private func validateIssuerIdentity(
        _ config: IssuerWellKnownConfiguration,
        specVersion: IssuerMetadataSpecVersion,
        expectedIdentifier: String,
        policy: DiscoveryPolicy
    ) throws {
        guard let declared = config.credentialIssuer?.trimmingCharacters(in: .whitespaces),
              !declared.isEmpty
        else {
            if specVersion == .v1_0 {
                throw DiscoveryError.invalid("The issuer configuration does not name an issuer")
            }
            return
        }

        let normalise: (String) -> String = { value in
            var value = value
            while value.hasSuffix("/") { value.removeLast() }
            return value
        }
        guard normalise(declared) != normalise(expectedIdentifier) else { return }

        // Always said out loud, even when not enforced: an identifier we did not ask for is worth
        // knowing about whether or not it stops the flow.
        debugPrint("### Issuer metadata fetched for \(expectedIdentifier) declares credential_issuer \(declared)")
        if policy.requireIssuerIdentifierMatch {
            throw DiscoveryError.invalid("The issuer configuration belongs to a different issuer (\(declared))")
        }
    }

    /// Section 12.2.4 states "This URL MUST use the https scheme" separately for
    /// `credential_endpoint`, `nonce_endpoint`, `deferred_credential_endpoint` and
    /// `notification_endpoint`. `credential_endpoint` is additionally REQUIRED for 1.0.
    ///
    /// The scheme check follows ``DiscoveryPolicy/allowedSchemes`` rather than the literal https,
    /// so a locally hosted issuer still works under ``DiscoveryPolicy/standard``.
    private func validateEndpoints(
        _ config: IssuerWellKnownConfiguration,
        specVersion: IssuerMetadataSpecVersion,
        policy: DiscoveryPolicy
    ) throws {
        let credentialEndpoint = config.credentialEndpoint?.trimmingCharacters(in: .whitespaces)
        if credentialEndpoint == nil || credentialEndpoint?.isEmpty == true {
            if specVersion == .v1_0 {
                throw DiscoveryError.invalid("The issuer configuration does not name a credential endpoint")
            }
        }

        let endpoints: [(String, String?)] = [
            ("credential endpoint", credentialEndpoint),
            ("nonce endpoint", config.nonceEndPoint),
            ("deferred credential endpoint", config.deferredCredentialEndpoint),
            ("notification endpoint", config.notificationEndPoint),
        ]
        for (name, value) in endpoints {
            guard let value = value?.trimmingCharacters(in: .whitespaces), !value.isEmpty else { continue }
            guard let scheme = URLComponents(string: value)?.scheme else {
                throw DiscoveryError.invalid("The issuer configuration names an invalid \(name): \(value)")
            }
            guard policy.allows(scheme: scheme) else {
                throw DiscoveryError.invalid("The issuer's \(name) uses an unsupported scheme: \(scheme)")
            }
        }
    }
}
