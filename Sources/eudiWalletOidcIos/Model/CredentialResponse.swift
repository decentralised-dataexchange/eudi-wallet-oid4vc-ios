//
//  CredentialResponse.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//

import Foundation

// MARK: - CredentialResponse
public struct CredentialResponse: Codable {
    var format, credential, acceptanceToken: String?
    var isDeferred, isPinRequired: Bool?
    var issuerConfig: IssuerWellKnownConfiguration?
    var authorizationConfig: AuthorisationServerWellKnownConfiguration?
    var credentialOffer: CredentialOffer?
    var error: Error?
    
    enum CodingKeys: String, CodingKey {
        case acceptanceToken = "acceptance_token"
        case format = "format"
        case credential = "credential"
    }
}
