//
//  File.swift
//  
//
//  Created by Mumthasir mohammed on 07/03/24.
//

import Foundation

// MARK: - CredentialOffer model
struct CredentialOffer: Codable {
    let credentialIssuer: String?
    let credentials: [Credential]?
    let grants: Grants?
    
    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case credentials, grants
    }
}

// MARK: - Credential
struct Credential: Codable {
    let format: String?
    let types: [String]?
    let trustFramework: TrustFramework?
    var credentialDefinition: CredentialDefinition?
    
    enum CodingKeys: String, CodingKey {
        case format, types
        case trustFramework = "trust_framework"
        case credentialDefinition
    }
}

// MARK: - CredentialDefinition
struct CredentialDefinition: Codable {
    var context: [String]?
    var types: [String]?

    enum CodingKeys: String, CodingKey {
        case context
        case types
    }
}

// MARK: - TrustFramework
struct TrustFramework: Codable {
    let name, type, uri: String?
}

// MARK: - Grants
struct Grants: Codable {
    let authorizationCode: AuthorizationCode?
    let urnIETFParamsOauthGrantTypePreAuthorizedCode: UrnIETFParamsOauthGrantTypePreAuthorizedCode?
    let authCode: UrnIETFParamsOauthGrantTypePreAuthorizedCode?

    enum CodingKeys: String, CodingKey {
        case authorizationCode = "authorization_code"
        case urnIETFParamsOauthGrantTypePreAuthorizedCode
        case authCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }
}

// MARK: - AuthorizationCode
struct AuthorizationCode: Codable {
    let issuerState: String?
    
    enum CodingKeys: String, CodingKey {
        case issuerState = "issuer_state"
    }
}

// MARK: - UrnIETFParamsOauthGrantTypePreAuthorizedCode
struct UrnIETFParamsOauthGrantTypePreAuthorizedCode: Codable {
    let preAuthorizedCode: String?
    let userPinRequired: Bool?
    
    enum CodingKeys: String, CodingKey {
        case preAuthorizedCode = "pre-authorized_code"
        case userPinRequired = "user_pin_required"
    }
}
