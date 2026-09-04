//
//  AuthorizationInputs.swift
//
//  What the authorization request is given.
//

import Foundation

/// Everything the offer and discovery steps established about this issuance.
///
/// These three always travel together and always come from the same place, so passing them as one
/// value removes three parameters and makes it impossible to hand in an issuer configuration
/// belonging to a different offer.
///
/// Mirrors `IssuanceSession` in the Android SDK.
public struct IssuanceSession {
    public let credentialOffer: CredentialOffer?
    public let issuerConfig: IssuerWellKnownConfiguration?
    public let authConfig: AuthorisationServerWellKnownConfiguration?

    public init(
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        authConfig: AuthorisationServerWellKnownConfiguration?
    ) {
        self.credentialOffer = credentialOffer
        self.issuerConfig = issuerConfig
        self.authConfig = authConfig
    }

    /// The `issuer_state` the offer carried, or `nil`.
    ///
    /// Section 4.1.1: on receiving it "the Wallet ... MUST include it in the subsequent
    /// Authorization Request". `nil` rather than blank, so it is omitted rather than sent empty --
    /// some authorization servers reject an empty `issuer_state`.
    var issuerState: String? {
        guard let state = credentialOffer?.grants?.authorizationCode?.issuerState,
              !state.isEmpty else { return nil }
        return state
    }
}

/// The wallet's own key identity. `jwk` signs the ID token when one is asked for.
public struct WalletIdentity {
    public let did: String
    public let jwk: [String: Any]?

    public init(did: String, jwk: [String: Any]? = nil) {
        self.did = did
        self.jwk = jwk
    }
}

/// The wallet unit attestation and its proof of possession.
///
/// The two are meaningless apart, so they belong in one value rather than as two parameters a
/// caller can mismatch.
public struct WalletAttestation {
    public let attestationJwt: String?
    public let proofOfPossession: String?

    public init(attestationJwt: String?, proofOfPossession: String?) {
        self.attestationJwt = attestationJwt
        self.proofOfPossession = proofOfPossession
    }

    /// The `~`-terminated form some issuers send is not accepted as a header value.
    var sanitisedAttestationJwt: String? {
        guard let jwt = attestationJwt, !jwt.isEmpty else { return nil }
        return jwt.hasSuffix("~") ? String(jwt.dropLast()) : jwt
    }
}

/// Whether the wallet makes the authorization request itself or hands a URL to a browser.
///
/// Replaces `isApiCallRequired`, which did not say what it selected. RFC 8252: a scanned offer must
/// go through the browser so the authorization server's session cookie lands there -- interactive
/// servers depend on it. ``inApp`` is for first-party, non-interactive flows only, such as the
/// wallet-provider attestation bootstrap.
public enum AuthorizationMode {
    case browser
    case inApp
}

/// Which credential is being asked for, when the caller wants to override what the session implies.
public struct CredentialSelection {
    public let format: String?
    public let docType: String?

    public init(format: String? = nil, docType: String? = nil) {
        self.format = format
        self.docType = docType
    }
}
