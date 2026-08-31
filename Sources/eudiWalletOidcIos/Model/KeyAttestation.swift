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
    /// iOS hardware evidence (Apple App Attest).
    public let iosAppAttest: IosAppAttestEvidence?

    public init(
        attestedKeys: [[String: Any]],
        keyPops: [String]? = nil,
        iosAppAttest: IosAppAttestEvidence? = nil
    ) {
        self.attestedKeys = attestedKeys
        self.keyPops = keyPops
        self.iosAppAttest = iosAppAttest
    }

    /// Serialise to the JSON shape the backend expects.
    public func toDictionary() -> [String: Any] {
        var dict: [String: Any] = ["attested_keys": attestedKeys]
        if let keyPops = keyPops, !keyPops.isEmpty {
            dict["key_pops"] = keyPops
        }
        if let evidence = iosAppAttest {
            dict["ios_app_attest"] = [
                "attestation_object": evidence.attestationObject,
                "key_id": evidence.keyId
            ]
        }
        return dict
    }
}

/// Response of the wallet-provider key-attestation endpoint.
public struct KeyAttestationResponse: Codable {
    public let keyAttestation: String?
    public let attestationType: String?
    public let keyStorage: [String]?
}
