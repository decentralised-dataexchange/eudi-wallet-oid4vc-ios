//
//  BatchCredentialOfferResponse.swift
//  eudiWalletOidcIos
//

import Foundation

/// Response of POST {baseUrl}/wallet-unit/request/batch.
/// `walletUnitAttestations` is index-aligned with the request's client_assertions.
public struct BatchCredentialOfferResponse: Codable {
    public let walletUnitAttestations: [String]?
    public let credentialIssuer: String?
    public let credentialOffer: String?
}
