//
//  KeyAttestationService.swift
//  eudiWalletOidcIos
//
//  ARF TS3 v1.5 Key Attestation (KA).
//
//  TS3 §2.2.2.1: the KA SHALL be generated and signed by the Wallet Provider —
//  the wallet never mints a KA itself. `requestKeyAttestation` sends the key
//  evidence (Apple App Attest for the hardware tier, key PoPs for the software
//  tier) to the wallet-provider backend, which verifies it and signs the KA.
//  The nonce is the ISSUER's c_nonce for the credential request (TS3 §2.2.2):
//  the wallet passes it to the wallet provider, the evidence is bound to it,
//  and the issuer — not the wallet provider — validates its freshness.
//

import Foundation

public class KeyAttestationService {

    public init() {}

    /// The credential configuration matching `type`, or nil.
    private static func config(
        _ issuerConfig: IssuerWellKnownConfiguration?,
        _ type: String?
    ) -> DataSharing? {
        guard let type = type, !type.isEmpty else { return nil }
        return issuerConfig?.credentialsSupported?.dataSharing?[type]
    }

    /// True when the issuer metadata declares
    /// proof_types_supported.jwt.key_attestations_required for `type`.
    public static func isRequired(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ) -> Bool {
        config(issuerConfig, type)?.keyAttestationsRequired == true
    }

    /// Whether the credential is device-bound, per TS3 2.2.2.2: a provider
    /// issuing non-device-bound attestations omits both proof_types_supported
    /// and cryptographic_binding_methods_supported from its metadata.
    ///
    /// Deliberately keyed off proof_types_supported rather than
    /// key_attestations_required: a device-bound issuer that omits the latter is
    /// still owed a KA under the SHALL half of 2.2.2.1, and gating on it would
    /// trade one violation for its opposite.
    public static func isDeviceBound(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ) -> Bool {
        guard let matching = config(issuerConfig, type) else { return false }
        return matching.hasProofTypesSupported == true
            || matching.cryptographicBindingMethodsSupported != nil
    }

    /// True when the issuer demands iso_18045_high key storage for the binding
    /// key (TS3 2.3.2). Drives whether the hardware tier is used at all.
    public static func requiresHighKeyStorage(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ) -> Bool {
        config(issuerConfig, type)?.keyStorage?.contains("iso_18045_high") == true
    }

    /// The KA that goes on a credential-request proof. Only a wallet-provider
    /// issued KA is accepted (TS3 §2.2.2.1) — there is no on-device fallback.
    /// Returns nil when no KA is wanted, or when one was wanted but the wallet
    /// provider did not deliver it (the issuer then rejects or warns).
    public static func forProof(walletProviderKa: String?, attach: Bool) -> String? {
        if let ka = walletProviderKa {
            return ka
        }
        if attach {
            print("KaWatch: KA wanted but the wallet provider did not deliver one — proof goes WITHOUT a KA (TS3: the wallet never self-mints)")
        }
        return nil
    }

    /// Proof of possession over the issuer c_nonce, signed BY the attested
    /// (binding) key, for the software tier. typ = key-pop+jwt.
    public static func generateKeyProofOfPossession(
        keyHandler: SecureKeyProtocol,
        nonce: String
    ) -> String? {
        let header = ([
            "alg": "ES256",
            "typ": "key-pop+jwt"
        ] as [String: Any]).toString() ?? ""
        let payload = ([
            "iat": Int(WalletClock.issuedAt().timeIntervalSince1970),
            "nonce": nonce
        ] as [String: Any]).toString() ?? ""
        let headerData = Data(header.utf8)
        return keyHandler.sign(
            payload: payload,
            header: headerData,
            withKey: keyHandler.generateSecureKey()?.privateKey
        )
    }

    /// Request the KA from the wallet provider (TS3 §2.2.2.1). `nonce` is the
    /// ISSUER's c_nonce for the credential request. The wallet unit must be
    /// registered and authorised on the wallet provider.
    public static func requestKeyAttestation(
        baseUrl: String,
        walletUnitAttestationJWT: String,
        walletUnitProofOfPossession: String,
        nonce: String,
        request: KeyAttestationRequest
    ) async -> KeyAttestationResponse? {
        let outcome = await sendKeyAttestation(
            baseUrl: baseUrl,
            walletUnitAttestationJWT: walletUnitAttestationJWT,
            walletUnitProofOfPossession: walletUnitProofOfPossession,
            nonce: nonce,
            request: request
        )
        return outcome.isSuccessful ? outcome.response : nil
    }

    /// Batch key attestation: one KA attesting every key in `attestedKeys`.
    /// Hardware tier: `iosAppAttest` carries one App Attest object per key,
    /// index-aligned, each attested with `nonce` in its challenge. Software
    /// tier: `keyPops` carries one proof per key. Keep the key count at or
    /// below the issuer's batch_size; a KA is single use, so extra keys are wasted.
    ///
    /// The HTTP status is kept: a 400 invalid_key_evidence (evidence count !=
    /// key count) is reported in the outcome. No client-side alignment check is
    /// done on purpose, so the wallet provider's own validation applies.
    public static func requestBatchKeyAttestation(
        baseUrl: String,
        walletUnitAttestationJWT: String,
        walletUnitProofOfPossession: String,
        nonce: String,
        attestedKeys: [[String: Any]],
        keyPops: [String]? = nil,
        iosAppAttest: [IosAppAttestEvidence]? = nil
    ) async -> KeyAttestationOutcome {
        await sendKeyAttestation(
            baseUrl: baseUrl,
            walletUnitAttestationJWT: walletUnitAttestationJWT,
            walletUnitProofOfPossession: walletUnitProofOfPossession,
            nonce: nonce,
            request: KeyAttestationRequest(attestedKeys: attestedKeys, keyPops: keyPops, iosAppAttest: iosAppAttest)
        )
    }

    private static func sendKeyAttestation(
        baseUrl: String,
        walletUnitAttestationJWT: String,
        walletUnitProofOfPossession: String,
        nonce: String,
        request: KeyAttestationRequest
    ) async -> KeyAttestationOutcome {
        guard let url = URL(string: "\(baseUrl)/wallet-provider/key-attestation") else {
            return KeyAttestationOutcome(httpCode: nil, response: nil, errorBody: "invalid url")
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let sanitisedWUA = walletUnitAttestationJWT.hasSuffix("~")
            ? String(walletUnitAttestationJWT.dropLast())
            : walletUnitAttestationJWT
        req.setValue(sanitisedWUA, forHTTPHeaderField: "OAuth-Client-Attestation")
        req.setValue(walletUnitProofOfPossession, forHTTPHeaderField: "OAuth-Client-Attestation-PoP")
        req.setValue(nonce, forHTTPHeaderField: "X-Wallet-Unit-Nonce")
        req.setValue("ios", forHTTPHeaderField: "X-Wallet-Unit-Platform")

        guard let body = try? JSONSerialization.data(withJSONObject: request.toDictionary(), options: []) else {
            return KeyAttestationOutcome(httpCode: nil, response: nil, errorBody: "request not serialisable")
        }
        req.httpBody = body

        let evidence: String
        if let appAttest = request.iosAppAttest, !appAttest.isEmpty {
            evidence = appAttest.count == 1 ? "ios_app_attest" : "ios_app_attest(\(appAttest.count))"
        } else {
            evidence = "key_pops(\(request.keyPops?.count ?? 0))"
        }
        print("KaWatch: POST \(url.absoluteString) keys=\(request.attestedKeys.count) evidence=\(evidence) nonce=\(nonce)")

        do {
            let (data, resp) = try await NetworkLogger.send(req, tag: "key-attestation")
            let status = (resp as? HTTPURLResponse)?.statusCode
            guard let status, (200..<300).contains(status) else {
                let error = String(data: data, encoding: .utf8)
                print("KaWatch: WP KA response \(status.map(String.init) ?? "-"): \(error ?? "")")
                return KeyAttestationOutcome(httpCode: status, response: nil, errorBody: error)
            }
            let ka = try? JSONDecoder().decode(KeyAttestationResponse.self, from: data)
            print("KaWatch: WP KA response \(status): attestationType=\(ka?.attestationType ?? "") keyStorage=\(ka?.keyStorage ?? []) attestedKeysCount=\(ka?.attestedKeysCount.map(String.init) ?? "-")")
            return KeyAttestationOutcome(httpCode: status, response: ka, errorBody: ka == nil ? String(data: data, encoding: .utf8) : nil)
        } catch {
            print("KaWatch: WP KA transport error: \(error)")
            return KeyAttestationOutcome(httpCode: nil, response: nil, errorBody: error.localizedDescription)
        }
    }
}
