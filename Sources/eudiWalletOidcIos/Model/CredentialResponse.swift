import Foundation
// MARK: - CredentialResponse
public struct CredentialResponse {
    public var format, credential, acceptanceToken: String?
    public var isDeferred, isPinRequired: Bool?
    public var issuerConfig: IssuerWellKnownConfiguration?
    public var authorizationConfig: AuthorisationServerWellKnownConfiguration?
    public var credentialOffer: CredentialOffer?
    public var error: EUDIError?
    public var notificationID: String?
    public var credentials: [CredentialItem]?
    public var interval: Double?
    
    
    public init(from: CredentialResponseV1) {
        format = from.format
        credential = from.credential
        acceptanceToken = from.acceptanceToken
        isDeferred = from.isDeferred
        isPinRequired = from.isPinRequired
        issuerConfig = from.issuerConfig
        authorizationConfig = from.authorizationConfig
        credentialOffer = from.credentialOffer
        error = from.error
        notificationID = from.notificationID
        credentials = from.credentials
        interval = from.interval
    }
    
    
    public init(from: CredentialResponseV2) {
        format = from.format
        credential = from.credential
        acceptanceToken = from.acceptanceToken
        isDeferred = from.isDeferred
        isPinRequired = from.isPinRequired
        issuerConfig = from.issuerConfig
        authorizationConfig = from.authorizationConfig
        credentialOffer = from.credentialOffer
        error = from.error
        notificationID = from.notificationID
        credentials = from.credentials
        interval = from.interval
    }
    
    public init(fromError: EUDIError) {
        error = fromError
    }
}


public struct CredentialItem: Codable {
    public let credential: String?
}
