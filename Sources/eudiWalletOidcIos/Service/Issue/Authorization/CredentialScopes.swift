//
//  CredentialScopes.swift
//
//  The `scope` values an issuer declares for the credentials an offer names.
//

import Foundation

/// The `scope` values an issuer declares for the credentials an offer names.
///
/// OpenID4VCI 1.0 section 5.1.2: "When the flow starts with a Credential Offer, the Wallet can use
/// the `credential_configuration_ids` parameter values to identify object(s) in the
/// `credential_configurations_supported` map in the Credential Issuer metadata parameter and **use
/// the `scope` parameter value from that object**."
///
/// Nothing in this SDK read that value before; the authorization request has always sent a fixed
/// `openid`. Reading it is behind ``AuthorizationRequestPolicy/useCredentialScopes`` because it
/// changes a parameter the authorization server acts on.
///
/// Only meaningful for 1.0 metadata, where `credential_configurations_supported` is keyed by
/// configuration id. Draft metadata has no such key, so this returns nothing for it and drafts keep
/// the scope they have always sent.
///
/// Mirrors `CredentialScopes` in the Android SDK.
enum CredentialScopes {

    static func forOffer(_ session: IssuanceSession) -> [String] {
        guard let supported = session.issuerConfig?.credentialsSupported?.dataSharing else { return [] }

        let configurationIds = (session.credentialOffer?.credentials ?? [])
            .compactMap { $0.types?.first }
            .filter { !$0.isEmpty }
        guard !configurationIds.isEmpty else { return [] }

        var seen = Set<String>()
        return configurationIds.compactMap { id -> String? in
            guard let scope = supported[id]?.scope, !scope.isEmpty else { return nil }
            return seen.insert(scope).inserted ? scope : nil
        }
    }
}
