//
//  IssuerMetadataSpecVersion.swift
//  eudiWalletOidcIos
//

import Foundation

/// Which revision of the OpenID4VCI Credential Issuer metadata an issuer published.
///
/// ``v1_0`` is the target and is always tried first. ``draft`` exists only to keep pre-1.0 issuers
/// working and is quarantined in the `Legacy` folder so it can be removed as a block.
public enum IssuerMetadataSpecVersion {

    /// OpenID4VCI 1.0: `credential_configurations_supported`, `authorization_servers`.
    case v1_0

    /// Pre-1.0 drafts: `credentials_supported`, singular `authorization_server`.
    case draft
}
