//
//  File.swift
//  
//
//  Created by Arun Raj on 05/06/24.
//

import Foundation

// MARK: - CredentialOffer model
public struct CredentialOfferResponse: Codable {
    var credentialIssuer: String?
    var credentials: [CredentialDataResponse]?
    var grants: GrantsResponse?
    var error: ErrorResponse?
    
    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case credentials, grants, error
    }
}

// MARK: - Credential
struct CredentialDataResponse: Codable {
    let format: String?
    let types: [String]?
    let trustFramework: TrustFrameworkResponse?
    var credentialDefinition: CredentialDefinitionResponse?
    
    enum CodingKeys: String, CodingKey {
        case format, types
        case trustFramework = "trust_framework"
        case credentialDefinition
    }
}

// MARK: - CredentialDefinition
struct CredentialDefinitionResponse: Codable {
    var context: [String]?
    var types: [String]?

    enum CodingKeys: String, CodingKey {
        case context
        case types
    }
}

// MARK: - TrustFramework
struct TrustFrameworkResponse: Codable {
    let name, type, uri: String?
}

// MARK: - Grants
struct GrantsResponse: Codable {
    let authorizationCode: AuthorizationCodeResponse?
    let urnIETFParamsOauthGrantTypePreAuthorizedCode: UrnIETFParamsOauthGrantTypePreAuthorizedCodeResponse?
    let authCode: UrnIETFParamsOauthGrantTypePreAuthorizedCodeResponse?

    enum CodingKeys: String, CodingKey {
        case authorizationCode = "authorization_code"
        case urnIETFParamsOauthGrantTypePreAuthorizedCode
        case authCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }
}

// MARK: - AuthorizationCode
struct AuthorizationCodeResponse: Codable {
    let issuerState: String?
    
    enum CodingKeys: String, CodingKey {
        case issuerState = "issuer_state"
    }
}

// MARK: - UrnIETFParamsOauthGrantTypePreAuthorizedCode
struct UrnIETFParamsOauthGrantTypePreAuthorizedCodeResponse: Codable {
    let preAuthorizedCode: String?
    let userPinRequired: Bool?
    
    enum CodingKeys: String, CodingKey {
        case preAuthorizedCode = "pre-authorized_code"
        case userPinRequired = "user_pin_required"
    }
}
