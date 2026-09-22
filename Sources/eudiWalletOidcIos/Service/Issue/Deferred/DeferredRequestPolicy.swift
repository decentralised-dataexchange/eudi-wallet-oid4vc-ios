//
//  DeferredRequestPolicy.swift
//

import Foundation

/// What the SDK sends and accepts when asking for a deferred credential.
///
/// ``standard`` is OpenID4VCI 1.0 as written; the flags exist to step back from it against an
/// issuer that has not caught up, not to opt into it.
///
/// Mirrors `DeferredRequestPolicy` in the Android SDK.
public struct DeferredRequestPolicy {

    /// Send `credential_identifier` alongside `transaction_id` when the caller has one.
    ///
    /// Section 9.1 permits it. On by default, because an issuer that deferred several credentials
    /// in one flow has no other way to tell which is being asked about — but it is a parameter an
    /// older issuer may reject, so it can be turned off.
    public var sendCredentialIdentifier: Bool

    /// Retry once when the deferred endpoint demands a DPoP nonce (RFC 9449 section 8).
    public var retryOnDPoPNonce: Bool

    public init(sendCredentialIdentifier: Bool = true, retryOnDPoPNonce: Bool = true) {
        self.sendCredentialIdentifier = sendCredentialIdentifier
        self.retryOnDPoPNonce = retryOnDPoPNonce
    }

    public static let standard = DeferredRequestPolicy()

    /// For an issuer still on the drafts: the bare handle, no retries.
    public static let legacy = DeferredRequestPolicy(
        sendCredentialIdentifier: false,
        retryOnDPoPNonce: false
    )
}
