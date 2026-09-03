//
//  AuthorizationServerSelector.swift
//  eudiWalletOidcIos
//

import Foundation

/// Where the chosen authorization server came from.
public enum AuthorizationServerSource {
    /// The only entry the issuer declared.
    case soleEntry
    /// The entry the credential offer pointed at.
    case offerHint
    /// The first of several entries, with no hint to narrow them.
    case firstOfSeveral
    /// Nothing was declared, so the Credential Issuer is its own authorization server
    /// (OpenID4VCI 1.0 section 12.2.4).
    case credentialIssuer
}

/// The chosen authorization server, and how it was chosen.
public struct AuthorizationServerSelection {
    public let identifier: String
    public let source: AuthorizationServerSource
    /// Every candidate that was available, in declaration order.
    public let candidates: [String]
}

/// Picks which authorization server to talk to, per OpenID4VCI 1.0 section 12.2.4.
///
/// Two of the specification's rules are commonly missed by hosts implementing this themselves: an
/// absent `authorization_servers` means the Credential Issuer is its own authorization server, and
/// an offer naming a server the issuer does not list must stop the flow rather than fall back.
///
/// `IssuerWellKnownConfiguration` already merges the draft-era singular `authorization_server` and
/// 1.0's `authorization_servers` into one array, so both revisions arrive here the same way.
public struct AuthorizationServerSelector {

    public init() {}

    /// - Parameter hint: the credential offer's `authorization_server` grant parameter, if any.
    /// - Throws: ``DiscoveryError/invalid(_:)`` when the specification says the flow must not proceed.
    public func select(
        issuerConfig: IssuerWellKnownConfiguration?,
        hint: String? = nil
    ) throws -> AuthorizationServerSelection {
        let servers = (issuerConfig?.authorizationServer ?? [])
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        let credentialIssuer = issuerConfig?.credentialIssuer?.trimmingCharacters(in: .whitespaces)
        let hint = hint?.trimmingCharacters(in: .whitespaces)

        if servers.isEmpty {
            // "If this parameter is omitted, the entity providing the Credential Issuer is also
            // acting as the Authorization Server."
            guard let credentialIssuer, !credentialIssuer.isEmpty else {
                throw DiscoveryError.invalid("The issuer configuration names no authorization server")
            }
            return AuthorizationServerSelection(
                identifier: credentialIssuer, source: .credentialIssuer, candidates: [credentialIssuer]
            )
        }

        guard let hint, !hint.isEmpty else {
            if servers.count > 1 {
                // The specification suggests narrowing by querying each server's metadata, for
                // example by grant_types_supported. That belongs to the authorization step, which
                // knows which grant it intends to use; until then the first is taken and said out loud.
                debugPrint("### Issuer declares \(servers.count) authorization servers and the offer named none; using the first")
            }
            return AuthorizationServerSelection(
                identifier: servers[0],
                source: servers.count == 1 ? .soleEntry : .firstOfSeveral,
                candidates: servers
            )
        }

        // "The Wallet MUST NOT proceed with the flow if the authorization_server Credential Offer
        // parameter value does not match any of the entries in the authorization_servers array."
        guard let matched = servers.first(where: { $0 == hint }) else {
            throw DiscoveryError.invalid(
                "The credential offer names an authorization server the issuer does not list (\(hint))"
            )
        }
        return AuthorizationServerSelection(
            identifier: matched,
            source: servers.count == 1 ? .soleEntry : .offerHint,
            candidates: servers
        )
    }

    /// The `authorization_server` hint carried by `offer`.
    ///
    /// The authorization-code grant is checked first, then the pre-authorized grant.
    public func hint(from offer: CredentialOffer?) -> String? {
        if let value = offer?.grants?.authorizationCode?.authorizationServer,
           !value.trimmingCharacters(in: .whitespaces).isEmpty {
            return value
        }
        let preAuth = offer?.grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode?.authorizationServer
        if let preAuth, !preAuth.trimmingCharacters(in: .whitespaces).isEmpty { return preAuth }
        return nil
    }
}
