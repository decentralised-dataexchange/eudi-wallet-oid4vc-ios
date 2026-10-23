//
//  PresentationRequestSource.swift
//  eudiWalletOidcIos
//

import Foundation

/// One way a verifier can hand an authorization request to the wallet.
///
/// OpenID4VP 1.0 carries the parameters in the request URI itself, in a `request` object by value
/// (RFC 9101 section 5.1) or behind a `request_uri` (RFC 9101 section 5.2 and OpenID4VP section
/// 5.10). Sources are consulted in registry order, so a new mechanism is one type plus one
/// registry entry.
protocol PresentationRequestSource {

    /// Short name, used in logs and in `ResolvedPresentationRequest.source`.
    var name: String { get }

    /// True when `data` carries a request this source can retrieve.
    func supports(_ data: String) -> Bool

    /// The request parameters, parsed but not yet validated or dereferenced.
    /// - Throws: `PresentationRequestError`
    func retrieve(_ data: String, policy: PresentationRequestPolicy) async throws -> PresentationRequest
}
