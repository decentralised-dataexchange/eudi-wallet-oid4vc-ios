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

    /// - Throws: ``CredentialRequestError/unusable(_:status:)`` when response encryption was asked
    ///   for and the ephemeral key could not be built. That used to be silent: the nil JWK went
    ///   into the dictionary, `JSONSerialization` threw inside a `try?`, and the request went out
    ///   with **no body at all**.
    static func build(
        subject: CredentialSubject,
        proof: String,
        session: IssuanceSession,
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

        // Section 8.2: "The `proofs` parameter MUST be present if the `proof_types_supported`
        // parameter is present in the `credential_configurations_supported` parameter of the Issuer
        // metadata." Both platforms previously keyed this off whether the configuration carried a
        // `credential_metadata` member, which is unrelated to whether the issuer wants the plural
        // form.
        if policy.usePluralProofs, declaresProofTypes(session: session, subject: subject) {
            params["proofs"] = [proofTypeJWT: [proof]]
        } else {
            params["proof"] = ["proof_type": proofTypeJWT, "jwt": proof]
        }

        if let responseEncryption = try responseEncryption(session: session, encryption: encryption) {
            params["credential_response_encryption"] = responseEncryption
        }

        return params
    }

    /// Whether the issuer declares `proof_types_supported` for **the credential being requested**.
    ///
    /// `hasProofTypesSupported` is already parsed onto the metadata model for the TS3 key
    /// attestation rules, so the correct trigger was one field away the whole time.
    static func declaresProofTypes(session: IssuanceSession, subject: CredentialSubject) -> Bool {
        guard let key = subject.metadataKey else { return false }
        return session.issuerConfig?.credentialsSupported?
            .dataSharing?[key]?.hasProofTypesSupported == true
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
