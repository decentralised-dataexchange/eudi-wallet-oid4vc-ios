//
//  TokenResponse.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//
import Foundation
import CryptoKit

// MARK: - TokenResponse (getAccessToken() Api call response model))
public struct TokenResponse: Codable {
    public var accessToken: String?
    public var tokenType: String?
    public var expiresIn: Int?
    public var idToken: String?
    public var cNonce: String?
    public var cNonceExpiresIn: Int?
    public var scope: String?
    public var error: EUDIError? // Optional error property
    public var refreshToken: String?
    public var lpid: String?
    public var lpidPop: String?
    public var authorizationDetails: [AuthorizationDetails]?
    public var dpopKey: P256.Signing.PrivateKey?

    /// A nonce the authorization server supplied in a `DPoP-Nonce` header, on the success or on a
    /// `use_dpop_nonce` challenge.
    ///
    /// RFC 9449 section 8.2: the client "MUST use the new nonce value supplied for the next token
    /// request and for all subsequent token requests until the authorization server supplies a new
    /// nonce". Carry it forward rather than discarding it.
    public var dpopNonce: String?
    
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case idToken = "id_token"
        case cNonce = "c_nonce"
        case cNonceExpiresIn = "c_nonce_expires_in"
        case scope = "scope"
        case refreshToken = "refresh_token"
        case authorizationDetails = "authorization_details"
    }
    
}

public struct AuthorizationDetails : Codable {
    
    public var type: String?
    public var credentialConfigId: String?
    public var credentialIdentifiers: [String]?
    
    enum CodingKeys: String, CodingKey {
        case type = "type"
        case credentialConfigId = "credential_configuration_id"
        case credentialIdentifiers = "credential_identifiers"
    }
    
}
