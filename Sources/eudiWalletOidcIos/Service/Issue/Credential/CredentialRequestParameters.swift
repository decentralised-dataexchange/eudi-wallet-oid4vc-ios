//
//  CredentialRequestParameters.swift
//

import Foundation

/// The credential request body, assembled once.
///
/// The shape is chosen by the ``CredentialSubject``, which the token response determines -- so the
/// five-branch `if`/`else` chain this replaces becomes a `switch` over three cases, and the two
/// identifiers section 8.2 declares mutually exclusive can no longer both be set.
///
/// The chain it replaces also wrote its legacy body **twice**: the first assignment was
/// unconditionally overwritten by the `version == "v1"` branch below it, and survived only when a
/// second, redundant metadata lookup returned nil.
///
/// Mirrors `CredentialRequestParameters` in the Android SDK.
enum CredentialRequestParameters {

    private static let proofTypeJWT = "jwt"
    private static let proofTypeAttestation = "attestation"

    /// - Throws: ``CredentialRequestError/unusable(_:status:)`` when response encryption was asked
    ///   for and the ephemeral key could not be built. That used to be silent: the nil JWK went
    ///   into the dictionary, `JSONSerialization` threw inside a `try?`, and the request went out
    ///   with **no body at all**.
    static func build(
        subject: CredentialSubject,
        proofs: CredentialProofs,
        session: IssuanceSession,
        token: TokenResponse?,
        encryption: CredentialEncryption?,
        policy: CredentialRequestPolicy
    ) throws -> [String: Any] {

        var params: [String: Any] = [:]

        switch subject {
        case let .byIdentifier(identifier, _):
            params["credential_identifier"] = identifier

        case let .byConfiguration(configurationId, _):
            params["credential_configuration_id"] = configurationId

        case let .legacyFormat(format, types, definitionTypes, vct, docType, _):
            // A body that names no credential cannot be satisfied by any issuer of any revision. It
            // is what `CredentialSubject.of` falls through to when a 1.0 issuer gave nothing to
            // name the credential by (no offer entry, no authorization_details), and sending it
            // would put a draft `format` next to 1.0 `proofs`.
            if subject.namesNothing {
                throw CredentialRequestError.unusable(
                    "The credential request names no credential: the offer entry and the "
                        + "token's authorization_details gave no configuration id or type"
                )
            }
            // 1.0 has no `format` member; these are the draft shapes, and the one case to delete
            // when draft support goes.
            if let format { params["format"] = format }
            if let types, !types.isEmpty { params["types"] = types }
            if let definitionTypes, !definitionTypes.isEmpty {
                params["credential_definition"] = ["type": definitionTypes]
            }
            if let vct, !vct.isEmpty { params["vct"] = vct }
            if let docType, !docType.isEmpty { params["doctype"] = docType }
        }

        // Section 8.2 of 1.0 defines only the plural `proofs`; the singular `proof` belongs to the
        // drafts (draft 13 has only `proof`, draft 14 accepts either). So `proofs` is the default,
        // and `proof` goes only to an issuer `IssuanceSession.isDraftIssuer` positively identifies
        // as a draft: the same answer that chose the subject's shape above, so the body cannot mix
        // a draft name with 1.0 proofs or the reverse.
        switch proofs {
        case let .attestation(keyAttestation):
            // §8.2: the attestation proof type carries the KA itself, and the issuer's c_nonce
            // lives inside it. There is no jwt proof to send.
            params["proofs"] = [proofTypeAttestation: [keyAttestation]]

        case let .jwt(jwtProofs):
            // A batch is more than one entry; §8.2's `proofs` is an array either way. The singular
            // `proof` is the pre-1.0 shape and cannot express a batch at all, so a batch always
            // takes the plural form whatever the issuer's revision -- and a policy that forbids
            // the plural form cannot send a batch. Failing here beats silently issuing one
            // credential of the several the caller asked for.
            let batch = jwtProofs.count > 1
            if batch, !policy.usePluralProofs {
                throw CredentialRequestError.unusable(
                    "A batch of \(jwtProofs.count) proofs needs the plural proofs form, "
                        + "which this CredentialRequestPolicy disables"
                )
            }
            if policy.usePluralProofs, batch || !session.isDraftIssuer(token: token) {
                params["proofs"] = [proofTypeJWT: jwtProofs]
            } else {
                params["proof"] = ["proof_type": proofTypeJWT, "jwt": jwtProofs.first ?? ""]
            }
        }

        if let responseEncryption = try responseEncryption(session: session, encryption: encryption) {
            params["credential_response_encryption"] = responseEncryption
        }

        return params
    }

    /// Section 10's `credential_response_encryption`, when the issuer supports the suite this SDK
    /// implements and the caller supplied a key to encrypt to.
    private static func responseEncryption(
        session: IssuanceSession,
        encryption: CredentialEncryption?
    ) throws -> [String: Any]? {
        let declared = session.issuerConfig?.credentialResponseEncryption
        guard declared?.algValuesSupported?.contains(alg) == true,
              declared?.encValuesSupported?.contains(contentEncryption) == true else { return nil }

        guard let responseKey = encryption?.responseKey else { return nil }
        guard let jwk = JWEEncryptor().generateEphemeralEncryptionJWK(privateKey: responseKey) else {
            throw CredentialRequestError.unusable(
                "The ephemeral key for the encrypted credential response could not be built"
            )
        }
        return ["jwk": jwk, "alg": alg, "enc": contentEncryption]
    }

    /// The one suite this SDK implements in both directions. Negotiating from
    /// `enc_values_supported` is deliberately out of this pass -- `JWEDecryptor` hardcodes
    /// `A128CBC-HS256` too, so declaring anything else here would produce a response the SDK
    /// cannot read.
    private static let alg = "ECDH-ES"
    static let contentEncryption = "A128CBC-HS256"
}
