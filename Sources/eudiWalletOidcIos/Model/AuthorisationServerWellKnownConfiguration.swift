//
//  AuthorisationServerWellKnownConfiguration.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//
import Foundation
// MARK: - AuthorisationServerWellKnownConfiguration
public struct AuthorisationServerWellKnownConfiguration: Codable {
    public var redirectUris: [String]?
    public var issuer, authorizationEndpoint, tokenEndpoint, jwksURI: String?
    public var scopesSupported, responseTypesSupported, responseModesSupported, grantTypesSupported: [String]?
    public var subjectTypesSupported, idTokenSigningAlgValuesSupported, requestObjectSigningAlgValuesSupported: [String]?
    public var requestParameterSupported, requestURIParameterSupported: Bool?
    public var tokenEndpointAuthMethodsSupported: [String]?
    public var requestAuthenticationMethodsSupported: RequestAuthenticationMethodsSupported?
    public var vpFormatsSupported: VpFormatsSupported?
    public var subjectSyntaxTypesSupported, subjectSyntaxTypesDiscriminations, subjectTrustFrameworksSupported, idTokenTypesSupported: [String]?
    public var requirePushedAuthorizationRequests: Bool?
    public var pushedAuthorizationRequestEndpoint: String?
    public var interactiveAuthorizationEndpoint: String?
    public var error: EUDIError?
    
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
        case requirePushedAuthorizationRequests = "require_pushed_authorization_requests"
        case pushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
        case interactiveAuthorizationEndpoint = "interactive_authorization_endpoint"
    }
}
// MARK: - RequestAuthenticationMethodsSupported
public struct RequestAuthenticationMethodsSupported: Codable {
    public var authorizationEndpoint: [String]?
    enum CodingKeys: String, CodingKey {
        case authorizationEndpoint = "authorization_endpoint"
    }
}
// MARK: - VpFormatsSupported
public struct VpFormatsSupported: Codable {
    public var jwtVp, jwtVc: JwtV?
    enum CodingKeys: String, CodingKey {
        case jwtVp = "jwt_vp"
        case jwtVc = "jwt_vc"
    }
}
// MARK: - JwtV
public struct JwtV: Codable {
    var algValuesSupported: [String]?
    enum CodingKeys: String, CodingKey {
        case algValuesSupported = "alg_values_supported"
    }
}
