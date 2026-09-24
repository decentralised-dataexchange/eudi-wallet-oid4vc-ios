//
//  KeyAttestation.swift
//  eudiWalletOidcIos
//
//  ARF TS3 v1.5 wallet-provider Key Attestation (KA).
//

import Foundation

/// iOS hardware evidence for the KA endpoint: an Apple App Attest attestation
/// object plus the App Attest key id, both base64-encoded. The App Attest
/// attestation is a throwaway that vouches for the Secure Enclave binding key;
/// its challenge commits to the binding key public JWK and the issuer c_nonce.
public struct IosAppAttestEvidence {
    public let attestationObject: String
    public let keyId: String

    public init(attestationObject: String, keyId: String) {
        self.attestationObject = attestationObject
        self.keyId = keyId
    }
}

/// Request body of the wallet-provider key-attestation endpoint
/// (POST {base}/wallet-provider/key-attestation). Field names match the
/// backend exactly.
public struct KeyAttestationRequest {
    /// Public JWKs of the attested credential-binding keys.
    public let attestedKeys: [[String: Any]]
    /// Software-tier proofs of possession, positionally aligned with attestedKeys.
    public let keyPops: [String]?
    /// iOS hardware evidence (Apple App Attest), one per attested key, index-aligned.
    public let iosAppAttest: [IosAppAttestEvidence]?

    public init(
        attestedKeys: [[String: Any]],
        keyPops: [String]? = nil,
        iosAppAttest: [IosAppAttestEvidence]? = nil
    ) {
        self.attestedKeys = attestedKeys
        self.keyPops = keyPops
        self.iosAppAttest = iosAppAttest
    }

    /// The `ios_app_attest` wire value: a single object for exactly one key (the
    /// original shape), a list index-aligned with `attested_keys` for two or more.
    static func appAttestWire(_ evidence: [IosAppAttestEvidence]?) -> Any? {
        guard let evidence, !evidence.isEmpty else { return nil }
        let objects = evidence.map { ["attestation_object": $0.attestationObject, "key_id": $0.keyId] }
        return objects.count == 1 ? objects[0] : objects
    }

    /// Serialise to the JSON shape the backend expects.
    public func toDictionary() -> [String: Any] {
        var dict: [String: Any] = ["attested_keys": attestedKeys]
        if let keyPops = keyPops, !keyPops.isEmpty {
            dict["key_pops"] = keyPops
        }
        if let evidence = Self.appAttestWire(iosAppAttest) {
            dict["ios_app_attest"] = evidence
        }
        return dict
    }
}

/// Response of the wallet-provider key-attestation endpoint.
public struct KeyAttestationResponse: Codable {
    public let keyAttestation: String?
    public let attestationType: String?
    public let keyStorage: [String]?
    /// How many keys the KA attests (batch key attestation).
    public let attestedKeysCount: Int?
}

/// Result of a batch key-attestation request, keeping the HTTP status so a
/// refusal such as 400 invalid_key_evidence reaches the caller.
public struct KeyAttestationOutcome {
    /// Nil when the request never reached the wallet provider.
    public let httpCode: Int?
    public let response: KeyAttestationResponse?
    public let errorBody: String?

    public var isSuccessful: Bool {
        guard let httpCode else { return false }
        return (200..<300).contains(httpCode) && response?.keyAttestation != nil
    }
}
