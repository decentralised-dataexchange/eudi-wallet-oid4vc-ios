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

    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case authorizationServer = "authorization_server"
        case credentialEndpoint = "credential_endpoint"
        case deferredCredentialEndpoint = "deferred_credential_endpoint"
        case credentialsSupported = "credentials_supported"
    }
}

// MARK: - CredentialsSupported
struct CredentialsSupported: Codable {
    var format: Format?
    var types: [String]?
    var trustFramework: TrustFramework?
    var display: [Display]?

    enum CodingKeys: String, CodingKey {
        case format, types
        case trustFramework = "trust_framework"
        case display
    }
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
}
