//
//  CredentialOffer.swift
//
//
//  Created by Mumthasir mohammed on 07/03/24.
//

import Foundation

// MARK: - CredentialOffer model
public struct CredentialOffer {
    public var credentialIssuer: String?
    public var credentials: [Credential]?
    public var grants: Grants?
    public var error: Error?
    
    public init(from: CredentialOfferResponse) {
        credentialIssuer = from.credentialIssuer
        
        if let credentialList = from.credentials, credentialList.count > 0{
            if let strCredentialList = credentialList as? [String]{
                credentials = [Credential(fromTypes: strCredentialList)]
            } else if let objCredentialList = credentialList as? [CredentialDataResponse]{
                credentials = credentialList.map({
                    let obj = $0 as! CredentialDataResponse
                    return Credential(from: obj)
                })
            }
            
        }
        grants = from.grants == nil ? nil : Grants(from: from.grants!)
        error = from.error == nil ? nil : Error(from: from.error!)
    }
    
    public init(fromError: Error) {
        error = fromError
    }
    
}

// MARK: - Credential
public struct Credential {
    public let format: String?
    public let types: [String]?
    public let trustFramework: TrustFramework?
    public var credentialDefinition: CredentialDefinition?
    
    init(from: CredentialDataResponse) {
        format = from.format
        types = from.types
        trustFramework = from.trustFramework == nil ? nil : TrustFramework(from: from.trustFramework!)
        credentialDefinition = from.credentialDefinition == nil ? nil : CredentialDefinition(from: from.credentialDefinition!)
    }
    
    init(fromTypes: [String]) {
        types = fromTypes
        format = nil
        trustFramework = nil
        credentialDefinition = nil
    }
}

// MARK: - CredentialDefinition
public struct CredentialDefinition {
    public var context: [String]?
    public var types: [String]?
    
    init(from: CredentialDefinitionResponse) {
        context = from.context
        types = from.types
    }
}

// MARK: - TrustFramework
public struct TrustFramework {
    public let name, type, uri: String?
    
    init(from: TrustFrameworkResponse) {
        name = from.name
        type = from.type
        uri = from.uri
    }
}

// MARK: - Grants
public struct Grants {
    public let authorizationCode: AuthorizationCode?
    public let urnIETFParamsOauthGrantTypePreAuthorizedCode: UrnIETFParamsOauthGrantTypePreAuthorizedCode?
    public let authCode: UrnIETFParamsOauthGrantTypePreAuthorizedCode?
    
    init(from: GrantsResponse) {
        authorizationCode = from.authorizationCode == nil ? nil : AuthorizationCode(from: from.authorizationCode!)
        urnIETFParamsOauthGrantTypePreAuthorizedCode = from.urnIETFParamsOauthGrantTypePreAuthorizedCode == nil ? nil : UrnIETFParamsOauthGrantTypePreAuthorizedCode(from: from.urnIETFParamsOauthGrantTypePreAuthorizedCode!)
        authCode = from.authCode == nil ? nil : UrnIETFParamsOauthGrantTypePreAuthorizedCode(from: from.authCode!)
    }
}

// MARK: - AuthorizationCode
public struct AuthorizationCode  {
    public let issuerState: String?
    
    init(from: AuthorizationCodeResponse) {
        issuerState = from.issuerState
    }
}

// MARK: - UrnIETFParamsOauthGrantTypePreAuthorizedCode
public struct UrnIETFParamsOauthGrantTypePreAuthorizedCode {
    public let preAuthorizedCode: String?
    public let userPinRequired: Bool?
    
    init(from: UrnIETFParamsOauthGrantTypePreAuthorizedCodeResponse) {
        preAuthorizedCode = from.preAuthorizedCode
        userPinRequired = from.userPinRequired
    }
}
