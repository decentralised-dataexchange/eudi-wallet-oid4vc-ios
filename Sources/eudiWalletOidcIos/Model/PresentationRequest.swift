//
//  PresentationRequest.swift
//
//
//  Created by Mumthasir mohammed on 18/03/24.
//
import Foundation
public struct PresentationRequest: Codable {
    public var state, clientId, redirectUri, responseType, responseMode, scope, nonce, requestUri: String?
    public var responseUri: String?
    public var presentationDefinition: String?
    public var clientMetaData: String?
    enum CodingKeys: String, CodingKey {
        case state = "state"
        case clientId = "client_id"
        case redirectUri = "redirect_uri"
        case responseUri = "response_uri"
        case responseType = "response_type"
        case responseMode = "response_mode"
        case scope = "scope"
        case nonce = "nonce"
        case requestUri = "request_uri"
        case presentationDefinition = "presentation_definition"
        case clientMetaData = "client_metadata"
    }
    public init(state: String?, clientId: String?, redirectUri: String?, responseUri: String?, responseType: String?, responseMode: String?, scope: String?, nonce: String?, requestUri: String?, presentationDefinition: String?, clientMetaData:  String?) {
        self.state = state
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.responseUri = responseUri
        self.responseType = responseType
        self.responseMode = responseMode
        self.scope = scope
        self.nonce = nonce
        self.requestUri = requestUri
        self.presentationDefinition = presentationDefinition
        self.clientMetaData = clientMetaData
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decodeIfPresent(String.self, forKey: .state)
        clientId = try container.decodeIfPresent(String.self, forKey: .clientId)
        redirectUri = try container.decodeIfPresent(String.self, forKey: .redirectUri)
        responseUri = try container.decodeIfPresent(String.self, forKey: .responseUri)
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
        if let clientMetaDataModel = try? container.decode(ClientMetaData.self, forKey: . clientMetaData) {
            clientMetaData = clientMetaDataModel.toJSONString()
        }
    }
}
public struct ClientMetaData: Codable {
    public var clientName, coverUri, description, location, logoUri: String?
    enum CodingKeys: String, CodingKey {
        case clientName = "client_name"
        case coverUri = "cover_uri"
        case description = "description"
        case location = "location"
        case logoUri = "logo_uri"
    }
    public init(clientName: String?, coverUri: String?, description: String?, location: String?, logoUri: String?) {
        self.clientName = clientName
        self.coverUri = coverUri
        self.description = description
        self.location = location
        self.logoUri = logoUri
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        clientName = try container.decodeIfPresent(String.self, forKey: .clientName)
        coverUri = try container.decodeIfPresent(String.self, forKey: .coverUri)
        description = try container.decodeIfPresent(String.self, forKey: .description)
        location = try container.decodeIfPresent(String.self, forKey: .location)
        logoUri = try container.decodeIfPresent(String.self, forKey: .logoUri)
    }
}
