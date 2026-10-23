//
//  ClientVerification.swift
//  eudiWalletOidcIos
//

import Foundation

/// How `ClientIdentifierVerifier` reacts when a request fails the rules of its client id prefix.
public enum ClientVerification {

    /// Refuse the request. OpenID4VP 1.0 as written.
    case enforced

    /// Run every check, log the result, carry it in `VerifierIdentity`, never refuse. For roll-out.
    case audit

    /// Do not check. `VerifierIdentity.verified` is always false.
    case off
}
