//
//  AuthorisationServerWellKnownConfiguration.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//

import Foundation

// MARK: - AuthorisationServerWellKnownConfiguration
public struct AuthorisationServerWellKnownConfiguration: Codable {
    var redirectUris: [String]?
    var issuer: String?
    var authorizationEndpoint: String?
    var tokenEndpoint: String?
    var jwksURI: String?
    var scopesSupported: [String]?
    var responseTypesSupported: [String]?
    var responseModesSupported: [String]?
    var grantTypesSupported: [String]?
    var subjectTypesSupported: [String]?
    var idTokenSigningAlgValuesSupported: [String]?
    var requestObjectSigningAlgValuesSupported: [String]?
    var requestParameterSupported: Bool?
    var requestURIParameterSupported: Bool?
    var tokenEndpointAuthMethodsSupported: [String]?
    var requestAuthenticationMethodsSupported: RequestAuthenticationMethodsSupported?
    var vpFormatsSupported: VpFormatsSupported?
    var subjectSyntaxTypesSupported: [String]?
    var subjectSyntaxTypesDiscriminations: [String]?
    var subjectTrustFrameworksSupported: [String]?
    var idTokenTypesSupported: [String]?

    enum CodingKeys: String, CodingKey {
        case redirectUris = "redirect_uris"
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case jwksURI = "jwks_uri"
        case scopesSupported = "scopes_supported"
        case responseTypesSupported = "response_types_supported"
        case responseModesSupported = "response_modes_supported"
        case grantTypesSupported = "grant_types_supported"
        case subjectTypesSupported = "subject_types_supported"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
        case requestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported"
        case requestParameterSupported = "request_parameter_supported"
        case requestURIParameterSupported = "request_uri_parameter_supported"
        case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
        case requestAuthenticationMethodsSupported = "request_authentication_methods_supported"
        case vpFormatsSupported = "vp_formats_supported"
        case subjectSyntaxTypesSupported = "subject_syntax_types_supported"
        case subjectSyntaxTypesDiscriminations = "subject_syntax_types_discriminations"
        case subjectTrustFrameworksSupported = "subject_trust_frameworks_supported"
        case idTokenTypesSupported = "id_token_types_supported"
    }
}

// MARK: - RequestAuthenticationMethodsSupported
struct RequestAuthenticationMethodsSupported: Codable {
    var authorizationEndpoint: [String]?

    enum CodingKeys: String, CodingKey {
        case authorizationEndpoint = "authorization_endpoint"
    }
}

// MARK: - VpFormatsSupported
struct VpFormatsSupported: Codable {
    var jwtVp, jwtVc: JwtV?

    enum CodingKeys: String, CodingKey {
        case jwtVp = "jwt_vp"
        case jwtVc = "jwt_vc"
    }
}

// MARK: - JwtV
struct JwtV: Codable {
    var algValuesSupported: [String]?

    enum CodingKeys: String, CodingKey {
        case algValuesSupported = "alg_values_supported"
    }
}
