//
//  BatchWalletAttestationResult.swift
//  eudiWalletOidcIos
//

import Foundation

/// One wallet instance attestation of a batch together with the key it is bound to.
public struct BatchWalletUnit {
    public let index: Int
    /// did:key of this unit's cnf key.
    public let did: String?
    /// The cnf key.
    public let keyHandler: SecureKeyProtocol
    public let clientAssertion: String
    /// walletUnitAttestations[index]; nil when the provider returned fewer.
    public let walletUnitAttestation: String?
}

/// Result of `WalletUnitAttestationService.initiateBatchWalletUnitAttestation`.
public struct BatchWalletAttestationResult {
    /// The client_id shared by every assertion of the batch.
    public let clientId: String
    /// App Attest challenge that was sent, for diagnostics.
    public let requestHash: String?
    /// Nil when the request never reached the server.
    public let httpCode: Int?
    public let errorBody: String?
    public let credentialOffer: String?
    public let credentialIssuer: String?
    /// Same size and order as the keys of the request.
    public let units: [BatchWalletUnit]

    public var attestations: [String] {
        units.compactMap { $0.walletUnitAttestation }
    }

    /// Unit 0 in the single-attestation shape. Nil when the provider did not
    /// return an attestation at index 0.
    public func toSingleResult() -> WalletUnitAttestationResponse? {
        guard let attestation = units.first?.walletUnitAttestation else { return nil }
        return WalletUnitAttestationResponse(
            credentialOffer: credentialOffer,
            walletUnitAttestation: attestation,
            credentialIssuer: credentialIssuer
        )
    }
}
