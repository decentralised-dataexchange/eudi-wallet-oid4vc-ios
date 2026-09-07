//
//  CredentialOutcome.swift
//

import Foundation

/// What the credential request produced.
///
/// Replaces a `CredentialResponse?` in which `nil` meant "something went wrong" and the caller had
/// to guess which of a dozen `return nil` sites it came from -- and in which "is this deferred?"
/// was answered by testing whether an `acceptance_token` happened to be non-nil.
///
/// Mirrors `CredentialOutcome` in the Android SDK.
public enum CredentialOutcome {

    /// The issuer returned credentials.
    ///
    /// - Parameter credentials: **every** credential the response carried. Section 8.3's
    ///   `credentials` is an array; the previous implementation surfaced only the first, and the
    ///   wallet read index 0 of that. A draft issuer returning a single `credential` arrives here
    ///   as a one-element array.
    /// - Parameter notificationId: section 11's handle, for telling the issuer the credential was
    ///   accepted or refused.
    /// - Parameter cNonce: a fresh nonce for the next request, which section 8.3 says the issuer
    ///   SHOULD return. Never modelled before, on either platform.
    case issued(credentials: [String], notificationId: String? = nil, cNonce: String? = nil)

    /// The credential is not ready; section 9's Deferred Credential Endpoint has it.
    ///
    /// Named from the outset even though the deferred *request* is the next pass -- recognising a
    /// deferred response and acting on it are separate things, and this is the recognising half.
    ///
    /// - Parameter transactionId: 1.0's handle. Draft issuers send `acceptance_token`; both land here.
    /// - Parameter interval: seconds to wait before asking again, when the issuer said.
    case deferred(transactionId: String, interval: Double? = nil)

    /// The request failed, with the issuer's own error code where it sent one.
    case failed(error: EUDIError)
}

public extension CredentialOutcome {

    /// The first credential, for callers that only ever wanted one.
    ///
    /// Provided so migrating call sites do not have to reach into the array, **not** as the way to
    /// read a multi-credential response -- use ``issued(credentials:notificationId:cNonce:)`` for that.
    var firstCredential: String? {
        if case let .issued(credentials, _, _) = self { return credentials.first }
        return nil
    }

    /// The failure, when there was one.
    var error: EUDIError? {
        if case let .failed(error) = self { return error }
        return nil
    }
}
