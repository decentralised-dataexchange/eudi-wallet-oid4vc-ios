//
//  TokenResponse.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//

import Foundation

// MARK: - TokenResponse (getAccessToken() Api call response model))
struct TokenResponse: Codable {
    let accessToken, tokenType: String
    let expiresIn: Int
    let idToken: String?
    let cNonce: String
    let cNonceExpiresIn: Int
    let scope: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case idToken = "id_token"
        case cNonce = "c_nonce"
        case cNonceExpiresIn = "c_nonce_expires_in"
        case scope = "scope"
    }
}
