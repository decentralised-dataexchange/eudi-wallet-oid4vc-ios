//
//  RedirectUriClientHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// Section 5.9.3 `redirect_uri`: "the original Client Identifier part is the Verifier's Redirect
/// URI (or Response URI when Response Mode direct_post is used). The Verifier MAY omit the
/// redirect_uri Authorization Request parameter." And: "Requests using the redirect_uri Client
/// Identifier Prefix cannot be signed because there is no method for the Wallet to obtain a
/// trusted key for verification."
///
/// So there is nothing to verify. The identifier fills in the missing URI, and a signature, if a
/// verifier sent one anyway, is ignored and said so. The `iar-post` modes post like `direct_post`
/// and are filled the same way, as this SDK has always done.
struct RedirectUriClientHandler: ClientIdentifierHandler {

    let prefixes: Set<ClientIdPrefix> = [.redirectUri]

    func verify(_ request: inout PresentationRequest, _ identifier: ClientIdentifier,
                policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        switch ResponseMode(from: request.responseMode ?? "") {
        case .directPost, .directPostJWT, .iarPost, .iarPostJWT:
            if request.responseUri?.isEmpty ?? true { request.responseUri = identifier.identifier }
        case .dcApi, .dcApiJWT, .none:
            if request.redirectUri?.isEmpty ?? true { request.redirectUri = identifier.identifier }
        }

        let signed = request.request.map { RequestObjectParser.looksLikeJwt($0) && !RequestObjectParser.isUnsigned($0) } ?? false
        return VerifierIdentity(
            identifier: identifier,
            verified: false,
            reason: signed ? "a redirect_uri request cannot be verified; its signature was ignored"
                : "the redirect_uri prefix carries no authentication")
    }
}
