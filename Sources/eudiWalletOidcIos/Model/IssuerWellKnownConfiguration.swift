//
//  IssuerWellKnownConfiguration.swift
//
//
//  Created by Mumthasir mohammed on 08/03/24.
//

import Foundation

// MARK: - IssuerWellKnownConfiguration
struct Display: Codable {
    let name: String?
    let location: String?
    let locale: String?
    let description: String?
}
struct TrustFrameworkInIssuer: Codable {
    let name: String?
    let type: String?
    let uri: String?
    let display: Display?
}
struct CredentialsSupported: Codable {
    let format: String?
    let types: [String]?
    let trustFramework: TrustFrameworkInIssuer?
    let display: DisplayOrArray?
}

// MARK: - CredentialsSupportedObject
struct CredentialsSupportedObjectType: Codable {
    var credentialsSupported: CredentialSupportedObject?

    enum CodingKeys: String, CodingKey {
        case credentialsSupported = "credentials_supported"
    }
}

// MARK: - CredentialObj
struct CredentialSupportedObject : Codable {
    var portableDocumentA1, parkingTicket, testDraft2, dataSharing: DataSharing?
    var drivingLicense: DataSharing?
    var format: Format?
    var types: [String]?
    var trustFramework: TrustFramework?
    var display: [DisplayElement]?
    
    enum CodingKeys: String, CodingKey {
        case portableDocumentA1 = "PortableDocumentA1"
        case parkingTicket = "Parking ticket"
        case testDraft2 = "Test draft 2"
        case dataSharing = "Data Sharing"
        case drivingLicense = "DrivingLicense"
    }
}

struct DisplayElement: Codable {
    var name: String?
    var locale: Locale?
}

enum Format: String, Codable {
    case jwtVc = "jwt_vc"
}

// MARK: - DataSharing
struct DataSharing: Codable {
    var format, scope: String?
    var cryptographicBindingMethodsSupported, cryptographicSuitesSupported: [String]?
    var display: [DataSharingDisplay]?
    
    enum CodingKeys: String, CodingKey {
        case format, scope
        case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
        case cryptographicSuitesSupported = "cryptographic_suites_supported"
        case display
    }
}

// MARK: - DataSharingDisplay
struct DataSharingDisplay: Codable {
    var name, locale, backgroundColor, textColor: String?

    enum CodingKeys: String, CodingKey {
        case name, locale
        case backgroundColor = "background_color"
        case textColor = "text_color"
    }
}

// MARK: - CredentialsSupportedObjectDisplay
struct CredentialsSupportedObjectDisplay: Codable {
    var name, location, locale: String?
    var cover, logo: Cover?
    var description: String?
}

// MARK: - Cover
struct Cover: Codable {
    var url: String?
    var altText: String?

    enum CodingKeys: String, CodingKey {
        case url
        case altText = "alt_text"
    }
}


public struct IssuerWellKnownConfiguration: Codable {
    let credentialIssuer: String?
    let authorizationServer: String?
    let credentialEndpoint: String?
    let deferredCredentialEndpoint: String?
    let display: DisplayOrArray?
    let credentialsSupported: SingleCredentialsSupportedOrArray?
    
    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case authorizationServer = "authorization_server"
        case credentialEndpoint =  "credential_endpoint"
        case deferredCredentialEndpoint = "deferred_credential_endpoint"
        case display = "display"
        case credentialsSupported = "credentials_supported"
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        credentialIssuer = try container.decode(String.self, forKey: .credentialIssuer)
        authorizationServer = try container.decode(String.self, forKey: .authorizationServer)
        credentialEndpoint = try container.decode(String.self, forKey: .credentialEndpoint)
        deferredCredentialEndpoint = try container.decode(String.self, forKey: .deferredCredentialEndpoint)
        
        if let singleCredentialSupported = try? container.decode(CredentialSupportedObject.self, forKey: .credentialsSupported) {
            credentialsSupported = .single(singleCredentialSupported)
        } else if let credentialSupportedArray = try? container.decode([CredentialsSupported].self, forKey: .credentialsSupported) {
            credentialsSupported = .array(credentialSupportedArray)
        } else {
            throw DecodingError.dataCorruptedError(forKey: .credentialsSupported, in: container, debugDescription: "Display value is missing or invalid.")
        }
        
        if let singleDisplay = try? container.decode(Display.self, forKey: .display) {
            display = .single(singleDisplay)
        } else if let displayArray = try? container.decode([Display].self, forKey: .display) {
            display = .array(displayArray)
        } else {
            throw DecodingError.dataCorruptedError(forKey: .display, in: container, debugDescription: "Display value is missing or invalid.")
        }
    }
}
enum DisplayOrArray: Codable {
    case single(Display)
    case array([Display])
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .single(let display):
            try container.encode(display)
        case .array(let displayArray):
            try container.encode(displayArray)
        }
    }
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let display = try? container.decode(Display.self) {
            self = .single(display)
        } else if let displayArray = try? container.decode([Display].self) {
            self = .array(displayArray)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Display value is missing or invalid.")
        }
    }
}


enum SingleCredentialsSupportedOrArray: Codable {
    case single(CredentialSupportedObject)
    case array([CredentialsSupported])
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .single(let credentialSupported):
            try container.encode(credentialSupported)
        case .array(let credentialSupportedArray):
            try container.encode(credentialSupportedArray)
        }
    }
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let credentialSupported = try? container.decode(CredentialSupportedObject.self) {
            self = .single(credentialSupported)
        } else if let credentialSupportedArray = try? container.decode([CredentialsSupported].self) {
            self = .array(credentialSupportedArray)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Credential supported value is missing or invalid.")
        }
    }
}
