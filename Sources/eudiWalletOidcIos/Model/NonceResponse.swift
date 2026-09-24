//
//  NonceResponse.swift
//  eudiWalletOidcIos
//

import Foundation

/// Body of the wallet provider's nonce endpoint ({service}/nonce or
/// {service}/wallet-provider/nonce).
public struct NonceResponse: Codable {
    public let nonce: String?
    /// The challenge for key attestation.
    public let cNonce: String?

    enum CodingKeys: String, CodingKey {
        case nonce
        case cNonce = "c_nonce"
    }
}
