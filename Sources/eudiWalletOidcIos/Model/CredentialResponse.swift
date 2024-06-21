//
//  CredentialResponse.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//

import Foundation

// MARK: - CredentialResponse
public struct CredentialResponse: Codable {
    public var format, credential, acceptanceToken: String?
    public var isDeferred, isPinRequired: Bool?
    public var issuerConfig: IssuerWellKnownConfiguration?
    public var authorizationConfig: AuthorisationServerWellKnownConfiguration?
    public var credentialOffer: CredentialOffer?
    public var error: EUDIError?
    
    enum CodingKeys: String, CodingKey {
        case acceptanceToken = "acceptance_token"
        case format = "format"
        case credential = "credential"
    }
}
