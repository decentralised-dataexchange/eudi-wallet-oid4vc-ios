//
//  IssuerWellKnownConfiguration.swift
//
//
//  Created by Mumthasir mohammed on 08/03/24.
//

import Foundation

// MARK: - IssuerWellKnownConfiguration
struct IssuerWellKnownConfiguration: Codable {
    var credentialIssuer, authorizationServer, credentialEndpoint, deferredCredentialEndpoint: String?
    var credentialsSupported: [CredentialsSupported]?
    var error: Error?
    var issuer, authorizationEndpoint, pushedAuthorizationRequestEndpoint, tokenEndpoint: String?
    var jwksURI: String?
    var scopesSupported, responseModesSupported, grantTypesSupported, subjectTypesSupported: [String]?
    var batchCredentialEndpoint: String?


    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case authorizationServer = "authorization_server"
        case credentialEndpoint = "credential_endpoint"
        case deferredCredentialEndpoint = "deferred_credential_endpoint"
        case credentialsSupported = "credentials_supported"
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case pushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
        case tokenEndpoint = "token_endpoint"
        case jwksURI = "jwks_uri"
        case scopesSupported = "scopes_supported"
        case responseModesSupported = "response_modes_supported"
        case grantTypesSupported = "grant_types_supported"
        case subjectTypesSupported = "subject_types_supported"
        case batchCredentialEndpoint = "batch_credential_endpoint"
    }
}

// MARK: - CredentialsSupported
struct CredentialsSupported: Codable {
    var format: Format?
    var types: [String]?
    var trustFramework: TrustFramework?
    var display: [Display]?
       var id: String?
       var cryptographicBindingMethodsSupported: [CryptographicBindingMethodsSupported]?
       var cryptographicSuitesSupported: [CryptographicSuitesSupported]?
    
    enum CodingKeys: String, CodingKey {
        case format, types, id
        case trustFramework = "trust_framework"
        case display
        case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
        case cryptographicSuitesSupported = "cryptographic_suites_supported"
    }
}

enum CryptographicBindingMethodsSupported: String, Codable {
    case did = "did"
}

enum CryptographicSuitesSupported: String, Codable {
    case edDSA = "EdDSA"
    case es256 = "ES256"
    case es256K = "ES256K"
    case rsa = "RSA"
}

// MARK: - Display
struct Display: Codable {
    var name: String?
    var locale: Locale?
}

enum Locale: String, Codable {
    case enGB = "en-GB"
}

enum Format: String, Codable {
    case jwtVc = "jwt_vc"
    case jwtVcJSON = "jwt_vc_json"
}
