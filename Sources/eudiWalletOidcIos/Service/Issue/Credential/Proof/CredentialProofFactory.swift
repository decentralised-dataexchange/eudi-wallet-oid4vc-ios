//
//  CredentialProofFactory.swift
//

import Foundation
import CryptoKit

/// Builds the `openid4vci-proof+jwt` that proves possession of the key a credential will be bound to.
///
/// Moved here from `Service/ProofService` because the credential request is the only thing that
/// uses it -- the same reasoning that put `IdTokenResponder` under `Authorization/IdToken/`. Unlike
/// Android, where the metadata helper had to stay behind because `data-wallet-android` calls it,
/// nothing outside this SDK ever called `ProofService`: it was `internal`, and the app's
/// equivalent is `IssueService.isCryptographicBindingMethodSupported`, which has not moved.
///
/// Section 8.2 and Appendix F: `typ` is `openid4vci-proof+jwt`; `aud` is the Credential Issuer
/// Identifier; `iat` is REQUIRED; `nonce` is REQUIRED when the issuer publishes a Nonce Endpoint;
/// and a key attestation travels in the `key_attestation` JOSE **header**, not in the body.
///
/// Mirrors `CredentialProofFactory` in the Android SDK.
enum CredentialProofFactory {

    /// 24 hours, in seconds.
    private static let lifetimeSeconds = 86_400

    /// - Parameter issuer: the proof's `iss`, which is the `client_id` the token was obtained
    ///   with. `nil` omits the claim entirely -- Appendix F.1: `iss` is left out when the token
    ///   came through anonymous access (§12.3's `pre-authorized_grant_anonymous_access_supported`).
    ///   Compute it with ``IssueService/proofIssuer(credentialOffer:preAuthorizedGrantAnonymousAccessSupported:clientId:did:)``
    ///   rather than passing the DID by reflex.
    /// - Parameter nonce: the issuer's `c_nonce`. Required when the session shows a nonce endpoint.
    /// - Parameter keyAttestation: the wallet-provider attestation, when one is owed. `nil`
    ///   attaches none.
    /// - Throws: ``CredentialRequestError``
    static func create(
        session: IssuanceSession,
        wallet: WalletIdentity,
        keyHandler: SecureKeyProtocol,
        issuer: String?,
        nonce: String?,
        subject: CredentialSubject,
        keyAttestation: String? = nil
    ) async throws -> String {

        // Section 8.2: the nonce is REQUIRED when a Nonce Endpoint exists. Omitting it silently --
        // which is what a nil nonce used to do -- produces `invalid_proof` a round trip later, with
        // nothing in the response saying which of the proof's parts was wrong.
        if nonce?.isEmpty != false, session.issuerConfig?.nonceEndPoint?.isEmpty == false {
            throw CredentialRequestError.noNonce
        }

        // Resolve the key ONCE. generateSecureKey() is load-or-create, so every extra call is a
        // chance to mint a replacement rather than observe the existing key -- which would both
        // change what gets signed and make any logging report a key that did not sign anything.
        let secureData = await keyHandler.generateSecureKey()
        let signingJwk = keyHandler.getJWK(publicKey: secureData?.publicKey ?? Data())

        // TS3 2.2.2.1: a jwt proof carrying a key attestation SHALL be signed with the key at index
        // 0 of attested_keys. Checked **before** signing: the old order signed first and threw the
        // signature away, and returned a bare nil the caller could not tell from any other failure.
        if let keyAttestation, !keyAttestation.isEmpty {
            let attestedKeys = jwtSegment(keyAttestation, 1)?["attested_keys"] as? [[String: Any]]
            let firstAttested = attestedKeys?.first?["x"] as? String
            if let firstAttested, let signingX = signingJwk?["x"] as? String,
               firstAttested != signingX {
                throw CredentialRequestError.proofFailed(
                    "The key attestation does not attest the key this proof would be signed with"
                )
            }
        }

        var header: [String: Any] = [
            "typ": "openid4vci-proof+jwt",
            "alg": proofAlgorithm,
        ]

        let bindingMethods = bindingMethods(for: session, subject: subject)
        if let didMethod = bindingMethods.first(where: { $0.hasPrefix("did") }) {
            header["kid"] = keyId(
                bindingMethod: didMethod, did: wallet.did, signingJwk: signingJwk
            )
        } else if subject.offerCredential?.trustFramework != nil {
            header["kid"] = keyId(
                bindingMethod: bindingMethods.first ?? "", did: wallet.did, signingJwk: signingJwk
            )
        } else {
            header["jwk"] = signingJwk
        }

        // ARF TS3 v1.5: the key attestation travels in this header parameter.
        if let keyAttestation, !keyAttestation.isEmpty {
            header["key_attestation"] = keyAttestation
        }

        // Fresh iat: the proof is replay-bound by the issuer c_nonce and, like DPoP, can be
        // rejected for a stale one.
        let issuedAt = Int(Date().epochTime) ?? 0
        var claims: [String: Any] = [
            "iat": issuedAt,
            "aud": session.issuerConfig?.credentialIssuer
                ?? session.credentialOffer?.credentialIssuer ?? "",
            "exp": issuedAt + lifetimeSeconds,
        ]
        if let nonce, !nonce.isEmpty { claims["nonce"] = nonce }
        // Appendix F.1: no `iss` at all when the access token was obtained anonymously.
        if let issuer, !issuer.isEmpty { claims["iss"] = issuer }

        guard let headerString = header.toString(),
              let payloadString = claims.toString() else {
            throw CredentialRequestError.proofFailed("The credential proof could not be encoded")
        }

        guard let proof = keyHandler.sign(
            payload: payloadString,
            header: Data(headerString.utf8),
            withKey: secureData?.privateKey
        ) else {
            throw CredentialRequestError.proofFailed("The credential proof could not be signed")
        }
        return proof
    }

    /// The binding methods the issuer declares for **this** credential.
    ///
    /// Keyed off the subject rather than `credentialTypes.last`: the previous version read the last
    /// element of a parallel array that the request body's other branches read the *first* of, so
    /// on a multi-credential offer the proof could be bound the way a different credential asked
    /// for.
    private static func bindingMethods(
        for session: IssuanceSession,
        subject: CredentialSubject
    ) -> [String] {
        guard let key = subject.metadataKey,
              let configuration = session.issuerConfig?.credentialsSupported?.dataSharing?[key]
        else { return [] }
        return configuration.cryptographicBindingMethodsSupported ?? []
    }

    /// The signature algorithm.
    ///
    /// **The key decides this, not the metadata.** Both key handlers -- the Secure Enclave one and
    /// the software one -- sign P-256, which can only produce ES256, so there is nothing here to
    /// select. `proof_signing_alg_values_supported` could only reveal that this wallet's key is one
    /// the issuer will not accept; the iOS metadata model does not carry that field today, so the
    /// check Android performs has no counterpart yet. Stated rather than faked: a branch that
    /// returns the same value either way while appearing to consult metadata is worse than none.
    private static let proofAlgorithm = "ES256"

    private static func keyId(
        bindingMethod: String,
        did: String,
        signingJwk: [String: Any]?
    ) -> String? {
        switch bindingMethod {
        case "did:jwk":
            guard let signingJwk, let encoded = base64URLEncodeJWK(signingJwk) else { return nil }
            // A DID URL, not a bare DID: did:jwk defines exactly one verification method, #0.
            return "did:jwk:\(encoded)#0"

        // RFC 7638. This used to be a SHA-256 over the whole JWK with `.sortedKeys`, so any
        // incidental member changed it, and Android used the key's own `kid` -- two platforms, two
        // values for the same binding method, neither the standard thumbprint.
        case "jwk":
            guard let signingJwk else { return nil }
            return JWKThumbprint.rfc7638(of: signingJwk)

        default:
            return "\(did)#\(did.replacingOccurrences(of: "did:key:", with: ""))"
        }
    }

    /// A JWK as the base64url of its JSON, for `did:jwk`.
    ///
    /// `JSONSerialization.data(withJSONObject:)` raises an **Objective-C** exception on an invalid
    /// top-level object, which a Swift `do`/`catch` cannot catch -- `data-wallet-ios` carries a
    /// comment about exactly this crash. `isValidJSONObject` is the guard that makes it safe.
    private static func base64URLEncodeJWK(_ jwk: [String: Any]) -> String? {
        guard JSONSerialization.isValidJSONObject(jwk),
              let data = try? JSONSerialization.data(withJSONObject: jwk) else { return nil }
        return data.base64URLEncodedString()
    }

    /// The decoded claims of one segment of a JWT.
    private static func jwtSegment(_ jwt: String, _ index: Int) -> [String: Any]? {
        let parts = jwt.split(separator: ".")
        guard parts.count > index,
              let data = Data(base64URLEncoded: String(parts[index])) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}

extension CredentialSubject {

    /// The key this credential is filed under in `credential_configurations_supported`.
    ///
    /// The offer entry's own type is preferred over ``configurationId``: for
    /// ``byIdentifier(credentialIdentifier:offerCredential:)`` the identifier names an *instance*
    /// the issuer allocated, not a configuration, so it is not a metadata key at all.
    var metadataKey: String? {
        switch self {
        // A ByConfiguration names the configuration id outright -- that *is* the metadata key,
        // and it is more authoritative than the offer entry's type.
        case let .byConfiguration(id, credential):
            return id.isEmpty ? (credential?.types?.first ?? credential?.doctype) : id
        default:
            return offerCredential?.types?.first ?? offerCredential?.doctype ?? configurationId
        }
    }
}
