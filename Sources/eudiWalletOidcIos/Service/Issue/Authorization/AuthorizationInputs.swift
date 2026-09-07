//
//  AuthorizationInputs.swift
//
//  What the authorization request is given.
//

import Foundation
import CryptoKit

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

    /// Whether the offer obliges the wallet to send a Transaction Code with the token request.
    ///
    /// Section 6.1: the code "MUST be present if a `tx_code` object was present in the Credential
    /// Offer (**including if the object was empty**)". So the test is the presence of the object,
    /// not whether it declares a length -- and not whether the caller happens to have a code.
    ///
    /// Ask this before prompting the user.
    public var requiresTransactionCode: Bool {
        credentialOffer?.grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode?.txCode != nil
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

    /// The DPoP key, when the token is to be sender-constrained.
    ///
    /// ARF TS3 requires this to be the key the attestation names in its `cnf` claim, which is why
    /// it lives here rather than beside the attestation as a parameter a caller can mismatch.
    public let dpopKey: P256.Signing.PrivateKey?

    /// The Secure-Enclave alternative to ``dpopKey``: the enclave signs, so the private key never
    /// leaves it and only the public JWK is available.
    public let dpopKeyHandler: SecureKeyProtocol?
    public let dpopKeyPublicJwk: [String: Any]?

    public init(
        attestationJwt: String?,
        proofOfPossession: String?,
        dpopKey: P256.Signing.PrivateKey? = nil,
        dpopKeyHandler: SecureKeyProtocol? = nil,
        dpopKeyPublicJwk: [String: Any]? = nil
    ) {
        self.attestationJwt = attestationJwt
        self.proofOfPossession = proofOfPossession
        self.dpopKey = dpopKey
        self.dpopKeyHandler = dpopKeyHandler
        self.dpopKeyPublicJwk = dpopKeyPublicJwk
    }

    /// The `~`-terminated form some issuers send is not accepted as a header value.
    var sanitisedAttestationJwt: String? {
        guard let jwt = attestationJwt, !jwt.isEmpty else { return nil }
        return jwt.hasSuffix("~") ? String(jwt.dropLast()) : jwt
    }

    /// Whether a DPoP key is available at all, by either route.
    var hasDPoPKey: Bool { dpopKey != nil || (dpopKeyHandler != nil && dpopKeyPublicJwk != nil) }

    /// The DPoP proof for [endpoint], carrying [nonce] when the server has demanded one.
    func dpopProof(for endpoint: String, nonce: String? = nil) -> String? {
        let claims: [String: Any] = nonce.map { ["nonce": $0] } ?? [:]
        if let dpopKeyHandler, let dpopKeyPublicJwk {
            return DPoPProofService.generateProof(
                tokenEndpoint: endpoint, keyHandler: dpopKeyHandler, publicJwk: dpopKeyPublicJwk, claims: claims
            )
        }
        guard let dpopKey else { return nil }
        return DPoPProofService.generateProof(tokenEndpoint: endpoint, dpopKey: dpopKey, claims: claims)
    }

    /// Whether the DPoP key is the one the attestation names in `cnf`, as ARF TS3 requires.
    ///
    /// `nil` when there is nothing to compare. A `false` is what the authorization server rejects
    /// as `invalid_client_attestation`, with nothing in the response saying which of the possible
    /// causes it was — so it is worth logging before the request goes out.
    var dpopKeyMatchesAttestation: Bool? {
        guard let ours = dpopKeyThumbprint,
              let theirs = attestationConfirmationThumbprint else { return nil }
        return ours == theirs
    }

    /// The `cnf.jwk` the attestation names, as an RFC 7638 thumbprint.
    private var attestationConfirmationThumbprint: String? {
        guard let payload = attestationJwt?.split(separator: "~").first?
                .split(separator: ".").dropFirst().first,
              let data = Data(base64URLEncoded: String(payload)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let cnf = (json["cnf"] as? [String: Any])?["jwk"] as? [String: Any]
        else { return nil }
        return Self.thumbprint(of: cnf)
    }

    /// The DPoP key we hold, as an RFC 7638 thumbprint.
    private var dpopKeyThumbprint: String? {
        if let dpopKeyPublicJwk { return Self.thumbprint(of: dpopKeyPublicJwk) }
        guard let dpopKey else { return nil }
        let raw = dpopKey.publicKey.rawRepresentation
        return Self.thumbprint(of: [
            "crv": "P-256",
            "x": raw.prefix(32).base64URLEncodedString(),
            "y": raw.suffix(32).base64URLEncodedString(),
        ])
    }

    /// RFC 7638: SHA-256 over the required members only, lexicographically ordered, no whitespace.
    private static func thumbprint(of jwk: [String: Any]) -> String? {
        guard let x = jwk["x"] as? String,
              let y = jwk["y"] as? String,
              let crv = jwk["crv"] as? String else { return nil }
        let canonical = "{\"crv\":\"\(crv)\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        return Data(SHA256.hash(data: Data(canonical.utf8))).base64URLEncodedString()
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
