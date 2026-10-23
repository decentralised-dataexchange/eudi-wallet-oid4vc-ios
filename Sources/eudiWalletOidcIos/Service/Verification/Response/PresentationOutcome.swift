//
//  PresentationOutcome.swift
//  eudiWalletOidcIos
//

import Foundation

/// What submitting a presentation produced.
public enum PresentationOutcome {

    /// The verifier accepted the response.
    ///
    /// - redirectUri: OpenID4VP 1.0 section 8.2: "When this parameter is present the Wallet MUST
    ///   redirect the user agent to this URI." Nil when the verifier sent none, in which case "the
    ///   Wallet is not required to perform any further steps".
    /// - location: the `Location` of a 3xx answer, which some verifiers send instead of the JSON
    ///   body. Not in 1.0; kept for them.
    /// - authorizationCode: the `code` an issuer's interactive authorization endpoint returns once
    ///   the presentation it asked for is accepted; the wallet exchanges it at the token endpoint to
    ///   continue issuance.
    case accepted(redirectUri: String?, location: String?, authorizationCode: String?)

    /// The response is ready but the host delivers it: the Digital Credentials API modes, where the
    /// platform carries `parameters` back to the verifier.
    case delivered(parameters: [String: String])

    /// Nothing was sent, or the verifier refused what was sent.
    case refused(EUDIError)
}
