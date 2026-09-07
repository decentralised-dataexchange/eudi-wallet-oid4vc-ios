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

    /// Adapts a ``CredentialOutcome`` back onto the shape callers already read.
    ///
    /// Kept so ``IssueService/processCredentialRequest(did:nonce:credentialOffer:issuerConfig:accessToken:format:credentialTypes:tokenResponse:authDetails:privateKey:isDpopSUpported:dpopKey:dpopKeyHandler:dpopKeyPublicJwk:attachKeyAttestation:keyAttestationJwt:)``
    /// can be deprecated rather than deleted, and both wallets keep compiling while they migrate.
    ///
    /// Note what is lost on the way through: `Issued` carries **every** credential and a `c_nonce`,
    /// and this type has nowhere to put the latter. New code should read the outcome.
    public init(from outcome: CredentialOutcome) {
        switch outcome {
        case let .issued(credentials, notificationId, _):
            credential = credentials.first
            self.credentials = credentials.map { CredentialItem(credential: $0) }
            notificationID = notificationId
            isDeferred = false

        case let .deferred(transactionId, interval):
            // Both the 1.0 `transaction_id` and the draft `acceptance_token` land here, and this
            // is the field callers test for deferral.
            acceptanceToken = transactionId
            self.interval = interval
            isDeferred = true

        case let .failed(error):
            self.error = error
        }
    }
}


public struct CredentialItem: Codable {
    public let credential: String?

    public init(credential: String?) {
        self.credential = credential
    }
}
