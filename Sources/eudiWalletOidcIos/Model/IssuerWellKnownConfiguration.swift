//
//  IssuerWellKnownConfiguration.swift
//
//
//  Created by Mumthasir mohammed on 08/03/24.
//

import Foundation

// MARK: - IssuerWellKnownConfiguration
public struct Display{
    public let name: String?
    public let location: String?
    public let locale: String?
    public let description: String?
    public var cover, logo: DisplayCover?
    public var backgroundColor, textColor: String?
    
    init(from: DisplayResponse) {
        name = from.name
        location = from.location
        locale = from.locale
        description = from.description
        cover = from.cover == nil ? nil : DisplayCover(from: from.cover!)
        logo = from.logo == nil ? nil : DisplayCover(from: from.logo!)
        backgroundColor = from.backgroundColor
        textColor = from.textColor
    }
}
public struct TrustFrameworkInIssuer {
    public let name: String?
    public let type: String?
    public let uri: String?
    public let display: Display?
    
    init(from: TrustFrameworkInIssuerResponse) {
        name = from.name
        type = from.type
        uri = from.uri
        display = from.display == nil ? nil : Display(from: from.display!)
    }
}
//struct CredentialsSupported: Codable {
//    let format: String?
//    let types: [String]?
//    let trustFramework: TrustFrameworkInIssuer?
//    let display: DisplayOrArray?
//}
//
//// MARK: - CredentialsSupportedObject
//struct CredentialsSupportedObjectType: Codable {
//    var credentialsSupported: CredentialSupportedObject?
//
//    enum CodingKeys: String, CodingKey {
//        case credentialsSupported = "credentials_supported"
//    }
//}

// MARK: - CredentialObj
public struct CredentialSupportedObject {
    
    public var dataSharing: [String : DataSharing]?
    
    init(from: [String:DataSharingResponse]) {
        
        dataSharing = from.mapValues({
            DataSharing(from: $0)
        })
        
    }
    
    init(from: [DataSharingOldFormatResponse]) {
        var ldataSharing = [String:DataSharing]()
        if from.count > 0{
            for item in from{
                let dataSharingVal = DataSharing(from: item)
                if let key = dataSharingVal.types?.last{
                    ldataSharing[key] = dataSharingVal
                }
            }
            
            if ldataSharing.count > 0{
                dataSharing = ldataSharing
            }
        }
    }

}

public struct DisplayElement {
    public var name: String?
    public var locale: Locale?
    
    init(from: DisplayElementResponse) {
        name = from.name
        locale = from.locale
    }
}

public struct IssuerCredentialDefinition {
    public var type: [String]?
    public var vct: String?
    
    init(from: IssuerCredentialDefinitionResponse) {
        type = from.type
        vct = from.vct
    }
}

//enum Format: String, Codable {
//    case jwtVc = "jwt_vc"
//}

// MARK: - DataSharing
public struct DataSharing {
    public var format, scope: String?
    public var cryptographicBindingMethodsSupported, cryptographicSuitesSupported: [String]?
    public var display: [Display]?
    public var types: [String]?
    public var trustFramework: TrustFramework?
    public var credentialDefinition: IssuerCredentialDefinition?
    
    init(from: DataSharingResponse) {
        format = from.format
        scope = from.scope
        cryptographicBindingMethodsSupported = from.cryptographicBindingMethodsSupported
        cryptographicSuitesSupported = from.cryptographicSuitesSupported
        if let dataSharingDisplayList = from.display, dataSharingDisplayList.count > 0{
            display = dataSharingDisplayList.map({ Display(from: $0) })
        }
        credentialDefinition = from.credentialDefinition == nil ? nil : IssuerCredentialDefinition(from: from.credentialDefinition!)
    }
    
    init(from: DataSharingOldFormatResponse) {
        format = from.format
        types = from.types
        trustFramework = from.trustFramework == nil ? nil : TrustFramework(from: from.trustFramework!)
        if let dataSharingDisplayList = from.display, dataSharingDisplayList.count > 0{
            display = dataSharingDisplayList.map({ Display(from: $0)})
        }
    }
}

// MARK: - CredentialsSupportedObjectDisplay
public struct CredentialsSupportedObjectDisplay {
    public var name, location, locale: String?
    public var cover, logo: DisplayCover?
    public var description: String?
}

// MARK: - Cover
public struct DisplayCover{
    public var url: String?
    public var altText: String?
    
    init(from: DisplayCoverResponse) {
        url = from.url
        altText = from.altText
    }
}


public struct IssuerWellKnownConfiguration {
    public let credentialIssuer: String?
    public let authorizationServer: String?
    public let credentialEndpoint: String?
    public let deferredCredentialEndpoint: String?
    public let display: [Display]?
    public let credentialsSupported: CredentialSupportedObject?
    public let error: EUDIError?
    
    public init(from: IssuerWellKnownConfigurationResponse) {
        credentialIssuer = from.credentialIssuer
        authorizationServer = from.authorizationServer ?? from.authorizationServers?[0] ?? ""
        credentialEndpoint = from.credentialEndpoint
        deferredCredentialEndpoint = from.deferredCredentialEndpoint
        
        if let displayList = from.display as? [DisplayResponse]
        {
            display = displayList.map({ Display(from: $0) })
        } else{
            display = nil
        }
        
        if let credentialsSupportList = from.credentialsSupported as? [[String:DataSharingResponse]], let firstObj = credentialsSupportList.first{
            credentialsSupported = CredentialSupportedObject(from: firstObj)
        } else if let credentialsSupportListOldFormat = from.credentialsSupported as? [DataSharingOldFormatResponse]{
            credentialsSupported = CredentialSupportedObject(from: credentialsSupportListOldFormat)
        } else{
            credentialsSupported = nil
        }
        
        error = nil
  
    }
    
    init(from: EUDIError) {
        error = from
        credentialIssuer = nil
        authorizationServer = nil
        credentialEndpoint = nil
        deferredCredentialEndpoint = nil
        display = nil
        credentialsSupported = nil
    }
    
    
}

