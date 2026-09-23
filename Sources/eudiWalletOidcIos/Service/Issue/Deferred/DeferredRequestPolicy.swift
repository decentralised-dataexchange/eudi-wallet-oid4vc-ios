//
//  DeferredRequestPolicy.swift
//

import Foundation

/// What the SDK sends and accepts when asking for a deferred credential.
///
/// ``standard`` sends 1.0 as written and accepts one thing 1.0 does not describe, because a real
/// issuer sends it — see ``acceptIntervalOnlyAsPending``. ``strict`` refuses that; ``legacy`` steps
/// back to the drafts.
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

    /// Treat a `200` whose body carries only an `interval` as "still pending", reusing the
    /// transaction id already being polled with.
    ///
    /// **This is not a shape OpenID4VCI 1.0 defines.** Section 9.3 says the Credential Issuer
    /// signals a pending credential with `400` and `issuance_pending`, and section 9.2 makes
    /// `transaction_id` REQUIRED in a `200` that defers again — `interval` is not a member of the
    /// success response at all. An issuer met in the field sends `200` with `interval` and no
    /// transaction id, and read strictly that is "neither a credential nor a transaction id", so
    /// polling stopped on a credential that was still coming.
    ///
    /// On by default so that issuer works, the same trade `DiscoveryPolicy.acceptDrafts` makes.
    /// Turn it off to hold an issuer to the specification.
    public var acceptIntervalOnlyAsPending: Bool

    public init(
        sendCredentialIdentifier: Bool = true,
        retryOnDPoPNonce: Bool = true,
        acceptIntervalOnlyAsPending: Bool = true
    ) {
        self.sendCredentialIdentifier = sendCredentialIdentifier
        self.retryOnDPoPNonce = retryOnDPoPNonce
        self.acceptIntervalOnlyAsPending = acceptIntervalOnlyAsPending
    }

    public static let standard = DeferredRequestPolicy()

    /// OpenID4VCI 1.0 as written: nothing the specification does not describe is accepted.
    public static let strict = DeferredRequestPolicy(acceptIntervalOnlyAsPending: false)

    /// For an issuer still on the drafts: the bare handle, no retries.
    public static let legacy = DeferredRequestPolicy(
        sendCredentialIdentifier: false,
        retryOnDPoPNonce: false
    )
}
