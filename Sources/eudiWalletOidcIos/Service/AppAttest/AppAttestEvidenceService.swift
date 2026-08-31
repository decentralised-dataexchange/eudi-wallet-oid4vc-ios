//
//  AppAttestEvidenceService.swift
//  eudiWalletOidcIos
//
//  Produces Apple App Attest hardware evidence for the wallet-provider Key
//  Attestation endpoint (ARF TS3 v1.5).
//
//  Apple cannot attest an arbitrary Secure Enclave key. So the credential
//  binding key is a separate Secure Enclave P-256 key (it signs the proof),
//  and a throwaway App Attest key produces an attestation whose clientDataHash
//  COMMITS to the binding key and the issuer c_nonce:
//
//     challenge       = utf8(cNonce) || DER(SubjectPublicKeyInfo(bindingKey))
//     clientDataHash  = SHA256(challenge)
//
//  The backend re-derives the same challenge from the received c_nonce and
//  attested_keys[0], so the composition MUST match byte-for-byte.
//

import Foundation
import DeviceCheck
import CryptoKit

@available(iOS 14.0, *)
public class AppAttestEvidenceService {

    public init() {}

    /// Whether Apple App Attest is available (real device, supported OS).
    public static var isSupported: Bool {
        DCAppAttestService.shared.isSupported
    }

    /// Produce App Attest evidence for `bindingKeyPublicKeyX963` (the 65-byte
    /// uncompressed P-256 point of the Secure Enclave binding key) bound to the
    /// issuer `cNonce`. Returns nil when App Attest is unavailable or fails
    /// (the caller then falls back to the software tier).
    public static func generateEvidence(
        bindingKeyPublicKeyX963: Data,
        cNonce: String
    ) async -> IosAppAttestEvidence? {
        let service = DCAppAttestService.shared
        guard service.isSupported else {
            print("KaWatch: App Attest not supported on this device")
            return nil
        }
        guard let publicKey = try? P256.Signing.PublicKey(x963Representation: bindingKeyPublicKeyX963) else {
            print("KaWatch: App Attest binding key not a valid P-256 point")
            return nil
        }
        var challenge = Data(cNonce.utf8)
        challenge.append(publicKey.derRepresentation)
        let clientDataHash = Data(SHA256.hash(data: challenge))

        do {
            // Reuses a key left un-attested by an earlier throttled attempt and
            // retries `serverUnavailable` on the same key and clientDataHash,
            // which is what preserves the device's App Attest risk metric.
            let result = try await AppAttestRetry.attest(
                service: service,
                clientDataHash: clientDataHash,
                keychainAccount: keyAttestationKeyAccount
            )
            return IosAppAttestEvidence(
                attestationObject: result.attestation.base64EncodedString(),
                keyId: result.keyId
            )
        } catch {
            print("KaWatch: App Attest evidence failed: \(error) - falling back to the software tier")
            return nil
        }
    }

    /// Keychain slot for the key-attestation path, separate from the wallet
    /// unit registration key so the two never consume each other's.
    private static let keyAttestationKeyAccount = "AppAttestKeyAttestationPendingKeyId"
}
