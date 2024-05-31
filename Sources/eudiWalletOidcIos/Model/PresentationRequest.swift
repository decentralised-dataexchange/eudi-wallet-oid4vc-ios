//
//  PresentationRequest.swift
//
//
//  Created by Mumthasir mohammed on 18/03/24.
//

import Foundation

public struct PresentationRequest: Codable {
    var state, clientId, redirectUri, responseType, responseMode, scope, nonce, requestUri: String?
    var presentationDefinition: String?

    enum CodingKeys: String, CodingKey {
        case state = "state"
        case clientId = "client_id"
        case redirectUri = "redirect_uri"
        case responseType = "response_type"
        case responseMode = "response_mode"
        case scope = "scope"
        case nonce = "nonce"
        case requestUri = "request_uri"
        case presentationDefinition = "presentation_definition"
    }

    public init(state: String?, clientId: String?, redirectUri: String?, responseType: String?, responseMode: String?, scope: String?, nonce: String?, requestUri: String?, presentationDefinition: String?) {
        self.state = state
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.responseType = responseType
        self.responseMode = responseMode
        self.scope = scope
        self.nonce = nonce
        self.requestUri = requestUri
        self.presentationDefinition = presentationDefinition
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decodeIfPresent(String.self, forKey: .state)
        clientId = try container.decodeIfPresent(String.self, forKey: .clientId)
        redirectUri = try container.decodeIfPresent(String.self, forKey: .redirectUri)
        responseType = try container.decodeIfPresent(String.self, forKey: .responseType)
        responseMode = try container.decodeIfPresent(String.self, forKey: .responseMode)
        scope = try container.decodeIfPresent(String.self, forKey: .scope)
        nonce = try container.decodeIfPresent(String.self, forKey: .nonce)
        requestUri = try container.decodeIfPresent(String.self, forKey: .requestUri)
        
        if let presentationDefinitionString = try? container.decode(String.self, forKey: .presentationDefinition) {
            presentationDefinition = presentationDefinitionString
        } else if let presentationDefinitionModel = try? container.decode(PresentationDefinitionModel.self, forKey: .presentationDefinition) {
            presentationDefinition = presentationDefinitionModel.toJSONString()
        } else {
            presentationDefinition = nil
        }
    }
}
