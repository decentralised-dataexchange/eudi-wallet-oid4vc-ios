//
//  CredentialOfferSpecVersion.swift
//  eudiWalletOidcIos
//

import Foundation

/// Which revision of the OpenID4VCI Credential Offer an issuer sent.
///
/// ``v1_0`` is the target: new work is built around it, and it is always tried first. ``draft``
/// exists only to keep pre-1.0 issuers working and is quarantined in the `Legacy` folders so it
/// can be removed as a block.
public enum CredentialOfferSpecVersion {

    /// OpenID4VCI 1.0: `credential_configuration_ids`, `tx_code`.
    case v1_0

    /// Pre-1.0 drafts: `credentials`, `user_pin_required`.
    case draft

    /// The value written to `CredentialOffer.version`.
    ///
    /// Compatibility shim. Hosts branch on this string, so it cannot change; the enum is the
    /// internal truth.
    var legacyVersionCode: String {
        switch self {
        case .v1_0: return "v2"
        case .draft: return "v1"
        }
    }
}
