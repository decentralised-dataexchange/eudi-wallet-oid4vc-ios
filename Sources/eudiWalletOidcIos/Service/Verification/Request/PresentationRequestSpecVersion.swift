//
//  PresentationRequestSpecVersion.swift
//  eudiWalletOidcIos
//

import Foundation

/// Which revision of the OpenID4VP Authorization Request a verifier sent.
///
/// `v1_0` is the target: new work is built around it and it is always tried first. `draft` exists
/// only to keep pre-1.0 verifiers working; its support lives in `Legacy/` so it can be removed as
/// a block.
public enum PresentationRequestSpecVersion {

    /// OpenID4VP 1.0: the query is a `dcql_query`, or the request carries no query at all.
    case v1_0

    /// Draft 20 and earlier: `presentation_definition`, `presentation_definition_uri` and
    /// `client_metadata_uri`, none of which exist in 1.0.
    case draft
}
