//
//  CredentialRequestPolicy.swift
//

import Foundation

/// What the SDK sends and accepts when making a credential request.
///
/// ``standard`` is OpenID4VCI 1.0 as written -- unlike ``TokenRequestPolicy``, where the defaults
/// step back from the specification to keep working requests working. The flags here exist to step
/// back from 1.0 against an issuer that has not caught up, not to opt into it.
///
/// Mirrors `CredentialRequestPolicy` in the Android SDK.
public struct CredentialRequestPolicy {

    /// Send the plural `proofs` object unless the issuer is positively identified as a pre-1.0
    /// draft (see ``IssuanceSession/isDraftIssuer(token:)``).
    ///
    /// Section 8.2 of 1.0 defines only `proofs`; the singular `proof` exists in the drafts alone.
    /// On by default, because that is the rule. Off sends the singular `proof` to every issuer; it
    /// changes the proof form only, so a caller stepping a draft issuer back by hand also passes a
    /// ``CredentialSubject/legacyFormat(format:types:credentialDefinitionTypes:vct:docType:offerCredential:)``
    /// so the body stays one revision throughout. A batch cannot be sent with this off.
    public var usePluralProofs: Bool

    /// Re-sign the proof and retry once when the issuer rejects it with a fresh nonce.
    ///
    /// Section 8.3.1: "The Credential Issuer MAY return a new `c_nonce` value in an error
    /// response." Applies to `invalid_proof` and `invalid_nonce`. Exactly once -- never a loop.
    public var retryOnStaleNonce: Bool

    /// Retry once when the credential endpoint demands a DPoP nonce (RFC 9449 section 8).
    ///
    /// The token endpoint already does this; the credential endpoint never has.
    public var retryOnDPoPNonce: Bool

    public init(
        usePluralProofs: Bool = true,
        retryOnStaleNonce: Bool = true,
        retryOnDPoPNonce: Bool = true
    ) {
        self.usePluralProofs = usePluralProofs
        self.retryOnStaleNonce = retryOnStaleNonce
        self.retryOnDPoPNonce = retryOnDPoPNonce
    }

    public static let standard = CredentialRequestPolicy()

    /// For an issuer that rejects the 1.0 shapes: singular `proof`, no retries.
    public static let legacy = CredentialRequestPolicy(
        usePluralProofs: false,
        retryOnStaleNonce: false,
        retryOnDPoPNonce: false
    )
}
