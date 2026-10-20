//
//  DeferredTransaction.swift
//

import Foundation

/// The handle the issuer gave out when it deferred a credential.
///
/// OpenID4VCI 1.0 section 9.1 names it `transaction_id` and makes it REQUIRED. The pre-1.0 drafts
/// called it `acceptance_token` and sent it as a **bearer token in the Authorization header** with
/// an empty body — not as a body parameter at all. Those are two different requests, which is why
/// `processDeferredCredentialRequest` branched on a stored `version` string and sent a different
/// body, authorization and content type on each side of it.
///
/// An enum puts that choice where it belongs: on the value itself. The caller holds a handle, not a
/// handle plus a version flag that has to agree with it.
///
/// Mirrors `DeferredTransaction` in the Android SDK.
public enum DeferredTransaction {

    /// Section 9.1: `transaction_id` in the request body, with the access token in the header.
    ///
    /// - Parameter credentialIdentifier: section 9.1 says this MAY be included; send it when the
    ///   credential was requested by identifier, so an issuer that deferred several in one flow
    ///   knows which is being asked about.
    case transactionId(String, credentialIdentifier: String? = nil)

    /// The pre-1.0 draft form: the handle *is* the bearer token and the body is empty.
    ///
    /// The single case to delete when draft support goes, as `CredentialSubject.legacyFormat` is.
    case legacyAcceptanceToken(String)

    /// The handle, whichever revision issued it.
    public var value: String {
        switch self {
        case let .transactionId(value, _): return value
        case let .legacyAcceptanceToken(value): return value
        }
    }
}
