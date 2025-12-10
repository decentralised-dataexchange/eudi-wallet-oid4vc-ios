//
//  IssuerWellKnownConfiguration.swift
//
//
//  Created by Mumthasir mohammed on 08/03/24.
//
import Foundation
// MARK: - IssuerWellKnownConfiguration
public struct Display: Codable{
    public let name: String?
    public let location: String?
    public let locale: String?
    public let description: String?
    public var bgImage, logo, cover: DisplayCover?
    public var backgroundColor, textColor: String?
    
    init(from: DisplayResponse) {
        name = from.name
        location = from.location
        locale = from.locale
        description = from.description
        bgImage = from.bgImage == nil ? nil : DisplayCover(from: from.bgImage!)
        logo = from.logo == nil ? nil : DisplayCover(from: from.logo!)
        cover = from.cover == nil ? nil : DisplayCover(from: from.cover!)
        backgroundColor = from.backgroundColor
        textColor = from.textColor
    }
    
    public init(mName: String?, mLocation:String?, mLocale: String?, mDescription: String?, mCover: DisplayCover?, mLogo: DisplayCover?, mBackgroundColor: String?, mTextColor: String?) {
           name = mName
           location = mLocation
           locale = mLocale
           description = mDescription
           bgImage = mCover
           logo = mLogo
           backgroundColor = mBackgroundColor
           textColor = mTextColor
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
// MARK: - CredentialObj
public struct CredentialSupportedObject: Codable {
    
    public var dataSharing: [String : DataSharing]?
    // version is used to identify whether the CredentialSupportedObject is an array or another type
    public var version: String?
    
    init(from: [String:DataSharingResponse]) {
        
        dataSharing = from.mapValues({
            DataSharing(from: $0)
        })
        version = "v2"
        
    }
    init(from: [String:DataSharingResponseV2]) {
        
        dataSharing = from.mapValues({
            DataSharing(from: $0)
        })
        version = "v2"
        
    }
    
    init(from: [DataSharingOldFormatResponse]) {
        var ldataSharing = [String:DataSharing]()
        version = "v1"
        if from.count > 0{
            for item in from{
                let dataSharingVal = DataSharing(from: item)
                if dataSharingVal.format == "mso_mdoc" {
                    if let key = dataSharingVal.docType{
                        ldataSharing[key] = dataSharingVal
                    }
                }
                else if let key = dataSharingVal.types?.last{
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
public struct IssuerCredentialDefinition: Codable {
    public var type: [String]?
    public var vct: String?
    
    init(from: IssuerCredentialDefinitionResponse) {
        type = from.type
        vct = from.vct
    }
}
// MARK: - DataSharing
public struct DataSharing: Codable {
    public var format, scope: String?
    public var cryptographicBindingMethodsSupported : [String]?
    public var display: [Display]?
    public var types: [String]?
    public var trustFramework: TrustFramework?
    public var credentialDefinition: IssuerCredentialDefinition?
    public var docType: String?
    public var vct: String?
    public let credentialMetadata: CredentialMetadata?
    
    init(from: DataSharingResponse) {
        format = from.format
        scope = from.scope
        cryptographicBindingMethodsSupported = from.cryptographicBindingMethodsSupported
        if let dataSharingDisplayList = from.display, dataSharingDisplayList.count > 0{
            display = dataSharingDisplayList.map({ Display(from: $0) })
        }
        credentialDefinition = from.credentialDefinition == nil ? nil : IssuerCredentialDefinition(from: from.credentialDefinition!)
        docType = from.docType
        credentialMetadata = from.credentialMetadata
    }
    init(from: DataSharingResponseV2) {
        format = from.format
        scope = from.scope
        cryptographicBindingMethodsSupported = from.cryptographicBindingMethodsSupported
        if let dataSharingDisplayList = from.display, dataSharingDisplayList.count > 0{
            display = dataSharingDisplayList.map({ Display(from: $0) })
        }
        credentialDefinition = from.credentialDefinition == nil ? nil : IssuerCredentialDefinition(from: from.credentialDefinition!)
        vct = from.vct
        docType = from.docType
        credentialMetadata = from.credentialMetadata
    }
    
    init(from: DataSharingOldFormatResponse) {
        format = from.format
        types = from.types
        docType = from.docType
        trustFramework = from.trustFramework == nil ? nil : TrustFramework(from: from.trustFramework!)
        if let dataSharingDisplayList = from.display, dataSharingDisplayList.count > 0{
            display = dataSharingDisplayList.map({ Display(from: $0)})
        }
        credentialMetadata = from.credentialMetadata
    }
}
// MARK: - CredentialsSupportedObjectDisplay
public struct CredentialsSupportedObjectDisplay {
    public var name, location, locale: String?
    public var cover, logo: DisplayCover?
    public var description: String?
}
// MARK: - Cover
public struct DisplayCover: Codable {
    public var uri: String?
    public var altText: String?
    public var url: String?
    
    init(from: DisplayCoverResponse) {
        uri = from.uri
        altText = from.altText
        url =  from.url
    }
    
    public init(mUrl: String?, mAltText: String?) {
        uri = mUrl
        altText = mAltText
        url = mUrl
    }
}
public struct IssuerWellKnownConfiguration: Codable {
    public let credentialIssuer: String?
    public let authorizationServer: [String]?
    public let credentialEndpoint: String?
    public let deferredCredentialEndpoint: String?
    public let display: [Display]?
    public let credentialsSupported: CredentialSupportedObject?
    public let error: EUDIError?
    public let notificationEndPoint: String?
    public let nonceEndPoint: String?
    public let credentialResponseEncryption: CredentialResponseEncryptionModel?
    public let credentialRequestEncryption: CredentialRequestEncryption?
    
    public init(from: IssuerWellKnownConfigurationResponse) {
        credentialIssuer = from.credentialIssuer
        var authServerArray: [String] = []
        if  from.authorizationServer == nil {
            authServerArray = from.authorizationServers ?? []
        } else {
            authServerArray = [from.authorizationServer ?? ""]
        }
        authorizationServer = authServerArray
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
        notificationEndPoint = from.notificationEndPoint
        nonceEndPoint = from.nonceEndpoint
        credentialResponseEncryption = from.credentialResponseEncryption
        credentialRequestEncryption = from.credentialRequestEncryption
        error = nil
  
    }
public init(from: IssuerWellKnownConfigurationResponseV2) {
        credentialIssuer = from.credentialIssuer
    var authServerArray: [String] = []
    if  from.authorizationServer == nil {
        authServerArray = from.authorizationServers ?? []
    } else {
        authServerArray = [from.authorizationServer ?? ""]
    }
    authorizationServer = authServerArray
        credentialEndpoint = from.credentialEndpoint
        deferredCredentialEndpoint = from.deferredCredentialEndpoint
        
        if let displayList = from.display as? [DisplayResponse]
        {
            display = displayList.map({ Display(from: $0) })
        } else{
            display = nil
        }
        
        if let credentialsSupportList = from.credentialsSupported as? [[String:DataSharingResponseV2]], let firstObj = credentialsSupportList.first{
            credentialsSupported = CredentialSupportedObject(from: firstObj)
        } else if let credentialsSupportListOldFormat = from.credentialsSupported as? [DataSharingOldFormatResponse]{
            credentialsSupported = CredentialSupportedObject(from: credentialsSupportListOldFormat)
        } else{
            credentialsSupported = nil
        }
        
        error = nil
        notificationEndPoint = from.notificationEndPoint
        nonceEndPoint = from.nonceEndpoint
        credentialResponseEncryption = from.credentialResponseEncryption
        credentialRequestEncryption = from.credentialRequestEncryption
    }
    
    public init(mCredentialIssuer: String?,
                mAuthorizationServer: String?,
                mCredentialEndpoint: String?,
                mDeferredCredentialEndpoint: String?,
                mDisplay: Display?) {
        credentialIssuer = nil
        authorizationServer = nil
        credentialEndpoint = nil
        deferredCredentialEndpoint = nil
        display = mDisplay != nil ? [mDisplay!] : nil
        credentialsSupported = nil
        error = nil
        notificationEndPoint = nil
        nonceEndPoint = nil
        credentialResponseEncryption = nil
        credentialRequestEncryption = nil
    }
    
    init(from: EUDIError) {
        error = from
        credentialIssuer = nil
        authorizationServer = nil
        credentialEndpoint = nil
        deferredCredentialEndpoint = nil
        display = nil
        credentialsSupported = nil
        notificationEndPoint = nil
        nonceEndPoint = nil
        credentialResponseEncryption = nil
        credentialRequestEncryption = nil
    }
}

public struct CredentialResponseEncryptionModel: Codable {
    public let algValuesSupported: [String]?
    public let encValuesSupported: [String]?
    
    enum CodingKeys: String, CodingKey {
        case algValuesSupported = "alg_values_supported"
        case encValuesSupported = "enc_values_supported"
    }
}


public struct CredentialRequestEncryption: Codable {
    public let jwks: [JWKData]?
    public let encryptionRequired: Bool?
    
    enum CodingKeys: String, CodingKey {
        case jwks = "jwks"
        case encryptionRequired = "encryption_required"
    }
}

public struct CredentialMetadata: Codable {
    public let display: [DisplayResponse]?
    public let claims: [ClaimData]?
}

public struct ClaimData: Codable {
    public var path: [String?]
}
