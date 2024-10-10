//
//  File.swift
//  
//
//  Created by oem on 10/10/24.
//

import Foundation

public struct CredentialOfferV2: Codable {
    var credentialIssuer: String?
    var credentialConfigurationIds: [AnyObject]?
    var grants: GrantsResponse?
    var error: ErrorResponse?
    
    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case credentialConfigurationIds = "credential_configuration_ids"
        case grants, error
    }

    
    public func encode(to encoder: Encoder) throws {
        
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.credentialIssuer = try container.decodeIfPresent(String.self, forKey: .credentialIssuer)
        if let stringArray = try? container.decode([String].self, forKey: .credentialConfigurationIds) {
            credentialConfigurationIds = stringArray as? [AnyObject]
        } else if let credentialArray = try? container.decode([CredentialDataResponse].self, forKey: .credentialConfigurationIds) {
            credentialConfigurationIds = credentialArray as? [AnyObject]
        } else {
            credentialConfigurationIds = nil
        }
        self.grants = try container.decodeIfPresent(GrantsResponse.self, forKey: .grants)
        self.error = try container.decodeIfPresent(ErrorResponse.self, forKey: .error)
    }

}

public struct TransactionCode: Codable {
    public let length: Int?
    public let inputMode: String?
    public let description: String?
    
    enum CodingKeys: String, CodingKey {
        case length
        case inputMode = "input_mode"
        case description
    }
    
    init(length: Int? = 0, inputMode: String = "", description: String = "") {
        self.length = length
        self.inputMode = inputMode
        self.description = description
    }
}


