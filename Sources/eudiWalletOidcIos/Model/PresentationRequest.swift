//
//  PresentationRequest.swift
//
//
//  Created by Mumthasir mohammed on 18/03/24.
//

import Foundation

public struct PresentationRequest: Codable {
    var state, clientId, redirectUri, responseType, responseMode, scope, nonce, requestUri, presentationDefinition: String?
    
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
}
