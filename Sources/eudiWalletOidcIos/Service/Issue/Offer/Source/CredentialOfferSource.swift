//
//  CredentialOfferSource.swift
//  eudiWalletOidcIos
//

import Foundation

/// One way an issuer can hand a credential offer to the wallet.
///
/// OpenID4VCI 1.0 defines two transfer mechanisms -- the `credential_offer` parameter and the
/// `credential_offer_uri` parameter -- and both are implemented here. Sources are consulted in
/// registry order, so supporting a new mechanism is one type plus one registry entry.
protocol CredentialOfferSource {

    /// Human-readable name, used in diagnostics.
    var name: String { get }

    /// `true` when `data` carries an offer this source can retrieve.
    func supports(_ data: String) -> Bool

    /// The raw credential offer JSON.
    func retrieve(_ data: String, policy: CredentialOfferPolicy) async throws -> Data
}
