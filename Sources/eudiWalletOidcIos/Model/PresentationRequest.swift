//
//  PresentationRequest.swift
//
//
//  Created by Mumthasir mohammed on 18/03/24.
//
import Foundation
public struct PresentationRequest: Codable {
    public var state, clientId, clientIDScheme,  redirectUri, responseType, responseMode, scope, nonce, requestUri: String?
    public var responseUri: String?
    public var presentationDefinition: String?
    public var clientMetaData: String?
    public var presentationDefinitionUri: String?
    public var clientMetaDataUri: String?
    public var transactionData: [String]?
    public var dcqlQuery: DCQLQuery?
    public var request: String?
    public var authSession: String?
    public var type: String?
    
    enum CodingKeys: String, CodingKey {
        case state = "state"
        case clientId = "client_id"
        case clientIDScheme = "client_id_scheme"
        case redirectUri = "redirect_uri"
        case responseUri = "response_uri"
        case responseType = "response_type"
        case responseMode = "response_mode"
        case scope = "scope"
        case nonce = "nonce"
        case requestUri = "request_uri"
        case presentationDefinition = "presentation_definition"
        case clientMetaData = "client_metadata"
        case presentationDefinitionUri = "presentation_definition_uri"
        case clientMetaDataUri = "client_metadata_uri"
        case transactionData = "transaction_data"
        case dcqlQuery = "dcql_query"
        case request = "request"
        case authSession = "auth_session"
        case type = "type"
    }
    
    public init(state: String?, clientId: String?, redirectUri: String?, responseUri: String?, responseType: String?, responseMode: String?, scope: String?, nonce: String?, requestUri: String?, presentationDefinition: String?, clientMetaData:  String?, presentationDefinitionUri: String?, clientMetaDataUri: String?, clientIDScheme: String?, transactionData: [String], dcqlQuery: DCQLQuery? = nil, request: String?, authSession: String?) {
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
        self.presentationDefinitionUri = presentationDefinitionUri
        self.clientMetaDataUri = clientMetaDataUri
        self.clientIDScheme = clientIDScheme
        self.transactionData = transactionData
        self.request = request
        self.dcqlQuery = dcqlQuery
        self.authSession = authSession
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decodeIfPresent(String.self, forKey: .state)
        clientId = try container.decodeIfPresent(String.self, forKey: .clientId)
        clientIDScheme = try container.decodeIfPresent(String.self, forKey: .clientIDScheme)
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
        if let clientMetaDataModel = try? container.decode(ClientMetaData.self, forKey: .clientMetaData) {
            clientMetaData = clientMetaDataModel.toJSONString()
        }
        presentationDefinitionUri = try container.decodeIfPresent(String.self, forKey: .presentationDefinitionUri)
        clientMetaDataUri = try container.decodeIfPresent(String.self, forKey: .clientMetaDataUri)
        transactionData = try container.decodeIfPresent([String].self, forKey: .transactionData)
//        if let transactionDataModel = try? container.decode(TransactionData.self, forKey: .transactionData) {
//            transactionData = transactionDataModel.toJSONString()
//        }
        if clientIDScheme == nil, let clientId = clientId, let scheme = clientId.split(separator: ":").first {
            clientIDScheme = String(scheme)
        }
        dcqlQuery = try container.decodeIfPresent(DCQLQuery.self, forKey: .dcqlQuery)
        authSession = try container.decodeIfPresent(String.self, forKey: .authSession)
        type = try container.decodeIfPresent(String.self, forKey: .type)
    }
}
public struct ClientMetaData: Codable {
    public var clientName, coverUri, description, location, logoUri, legalPidAttestation, legalPidAttestationPop, authorizationEncryptedResponseAlg, authorizationEncryptedResponseEnc, idTokenEncryptedResponseAlg, id_token_encrypted_response_enc, jwks_uri, id_token_signed_response_alg : String?
    public var subject_syntax_types_supported: [String]?
    public var jwks: JWKS?
    
    enum CodingKeys: String, CodingKey {
        case clientName = "client_name"
        case coverUri = "cover_uri"
        case description = "description"
        case location = "location"
        case logoUri = "logo_uri"
        case legalPidAttestation = "legal_pid_attestation"
        case legalPidAttestationPop = "legal_pid_attestation_pop"
        case authorizationEncryptedResponseAlg = "authorization_encrypted_response_alg"
        case authorizationEncryptedResponseEnc = "authorization_encrypted_response_enc"
        case idTokenEncryptedResponseAlg = "id_token_encrypted_response_alg"
        case id_token_encrypted_response_enc = "id_token_encrypted_response_enc"
        case jwks_uri = "jwks_uri"
        case subject_syntax_types_supported = "subject_syntax_types_supported"
        case id_token_signed_response_alg = "id_token_signed_response_alg"
        case jwks = "jwks"
    }
    
    public init(clientName: String?, coverUri: String?, description: String?, location: String?, logoUri: String?, legalPidAttestation: String?, legalPidAttestationPop: String?, authorizationEncryptedResponseAlg: String? = nil, authorizationEncryptedResponseEnc: String? = nil, idTokenEncryptedResponseAlg: String? = nil, id_token_encrypted_response_enc: String? = nil, jwks_uri: String? = nil,subject_syntax_types_supported: [String]? = nil, id_token_signed_response_alg: String? = nil, jwks: JWKS? = nil) {
        self.clientName = clientName
        self.coverUri = coverUri
        self.description = description
        self.location = location
        self.logoUri = logoUri
        self.legalPidAttestation = legalPidAttestation
        self.legalPidAttestationPop = legalPidAttestationPop
        self.authorizationEncryptedResponseAlg = authorizationEncryptedResponseAlg
        self.authorizationEncryptedResponseEnc = authorizationEncryptedResponseEnc
        self.idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg
        self.id_token_encrypted_response_enc = id_token_encrypted_response_enc
        self.jwks_uri = jwks_uri
        self.subject_syntax_types_supported = subject_syntax_types_supported
        self.id_token_signed_response_alg = id_token_signed_response_alg
        self.jwks = jwks
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        clientName = try container.decodeIfPresent(String.self, forKey: .clientName)
        coverUri = try container.decodeIfPresent(String.self, forKey: .coverUri)
        description = try container.decodeIfPresent(String.self, forKey: .description)
        location = try container.decodeIfPresent(String.self, forKey: .location)
        logoUri = try container.decodeIfPresent(String.self, forKey: .logoUri)
        legalPidAttestation = try container.decodeIfPresent(String.self, forKey: .legalPidAttestation)
        legalPidAttestationPop = try container.decodeIfPresent(String.self, forKey: .legalPidAttestationPop)
        authorizationEncryptedResponseAlg = try container.decodeIfPresent(String.self, forKey: .authorizationEncryptedResponseAlg)
        authorizationEncryptedResponseEnc = try container.decodeIfPresent(String.self, forKey: .authorizationEncryptedResponseEnc)
        idTokenEncryptedResponseAlg = try container.decodeIfPresent(String.self, forKey: .idTokenEncryptedResponseAlg)
        id_token_encrypted_response_enc = try container.decodeIfPresent(String.self, forKey: .id_token_encrypted_response_enc)
        jwks_uri = try container.decodeIfPresent(String.self, forKey: .jwks_uri)
        subject_syntax_types_supported = try container.decodeIfPresent([String].self, forKey: .subject_syntax_types_supported)
        id_token_signed_response_alg = try container.decodeIfPresent(String.self, forKey: .id_token_signed_response_alg)
        jwks = try container.decodeIfPresent(JWKS.self, forKey: .jwks)
    }
    
}
public struct JWKS: Codable {
    let keys: [JWKData]?
}
public struct JWKData: Codable {
    let kty: String?
    let use: String?
    let crv: String?
    let kid: String?
    let x: String?
    let y: String?
    let alg: String?
}
public struct TransactionData: Codable {
    public var type: String?
    public var credentialIDs: [String]?
    public var paymentData: PaymentData?
    enum CodingKeys: String, CodingKey {
        case type = "type"
        case credentialIDs = "credential_ids"
        case paymentData = "payment_data"
    }
    public init(type: String?, credentialIDs: [String]?, paymentData: PaymentData?) {
        self.type = type
        self.credentialIDs = credentialIDs
        self.paymentData = paymentData
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        type = try container.decodeIfPresent(String.self, forKey: .type)
        credentialIDs = try container.decodeIfPresent([String].self, forKey: .credentialIDs)
        paymentData = try container.decodeIfPresent(PaymentData.self, forKey: .paymentData)
    }
    
}
public struct PaymentData: Codable {
    public var payee: String?
    public var currencyAmount: CurrencyAmount?
    
    enum CodingKeys: String, CodingKey {
        case payee = "payee"
        case currencyAmount = "currency_amount"
    }
    public init(payee: String?, currencyAmount: CurrencyAmount?) {
        self.payee = payee
        self.currencyAmount = currencyAmount
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        payee = try container.decodeIfPresent(String.self, forKey: .payee)
        currencyAmount = try container.decodeIfPresent(CurrencyAmount.self, forKey: .currencyAmount)
    }
}
public struct CurrencyAmount: Codable {
    public var currency: String?
    public var value: Double?
    
    enum CodingKeys: String, CodingKey {
        case currency = "currency"
        case value = "value"
    }
    public init(currency: String?, value: Double?) {
        self.currency = currency
        self.value = value
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        currency = try container.decodeIfPresent(String.self, forKey: .currency)
        value = try container.decodeIfPresent(Double.self, forKey: .value)
    }
}

public struct DCQLQuery: Codable {
    public var credentials: [CredentialItems]
    public var credentialSets: [CredentialSet]?
    
    enum CodingKeys: String, CodingKey {
        case credentials = "credentials"
        case credentialSets = "credential_sets"
    }
    
    public init(credentials: [CredentialItems], credentialSets: [CredentialSet]? = nil) {
        self.credentials = credentials
        self.credentialSets = credentialSets
    }
}

public struct CredentialItems: Codable {
    public let id: String
    public let format: String
    public let meta: Meta
    public let claims: [Claim]
    
    public init(id: String, format: String, meta: Meta, claims: [Claim]) {
        self.id = id
        self.format = format
        self.meta = meta
        self.claims = claims
    }
}

public struct CredentialSet: Codable {
    public let required: Bool?
    public let options: [[String]]
    
    public init(required: Bool? = nil, options: [[String]]) {
        self.required = required
        self.options = options
    }
}

public enum Meta: Codable {
    case dcSDJWT(DCSDJWTMeta)
    case msoMdoc(MSOMdocMeta)
    case jwt(JWTMeta)

    enum CodingKeys: String, CodingKey {
        case vct_values
        case doctype_value
        case type_values
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let vctValues = try? container.decode([String].self, forKey: .vct_values) {
            self = .dcSDJWT(DCSDJWTMeta(vctValues: vctValues))
        } else if let doctypeValue = try? container.decode(String.self, forKey: .doctype_value) {
            self = .msoMdoc(MSOMdocMeta(doctypeValue: doctypeValue))
        } else if let typeValue = try? container.decode([[String]].self, forKey: .type_values) {
            self = .jwt(JWTMeta(typeValues: typeValue))
        } else {
            throw DecodingError.dataCorruptedError(forKey: .vct_values, in: container, debugDescription: "Unknown meta type")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .dcSDJWT(let meta):
            try container.encode(meta.vctValues, forKey: .vct_values)
        case .msoMdoc(let meta):
            try container.encode(meta.doctypeValue, forKey: .doctype_value)
        case .jwt(let meta):
            try container.encode(meta.typeValues, forKey: .type_values)
        }
    }
    
    public var extractedCredentialTypes: [String] {
            switch self {
            case .dcSDJWT(let meta):
                return meta.vctValues
            case .msoMdoc(let meta):
                return [meta.doctypeValue]
            case .jwt(let meta):
                return meta.typeValues.flatMap { $0 }
            }
        }
}

public struct DCSDJWTMeta: Codable {
    public let vctValues: [String]
    
    public init(vctValues: [String]) {
        self.vctValues = vctValues
    }
}

public struct MSOMdocMeta: Codable {
    public let doctypeValue: String
    
    public init(doctypeValue: String) {
        self.doctypeValue = doctypeValue
    }
}

public struct JWTMeta: Codable {
    public let typeValues: [[String]]
    
    public init(typeValues: [[String]]) {
        self.typeValues = typeValues
    }
}

public enum Claim: Codable {
    case pathClaim(PathClaim)
    case namespacedClaim(NamespacedClaim)

    enum CodingKeys: String, CodingKey {
        case path
        case namespace
        case claim_name
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let path = try? container.decode([String].self, forKey: .path) {
            self = .pathClaim(PathClaim(path: path))
        } else if let namespace = try? container.decode(String.self, forKey: .namespace),
                  let claimName = try? container.decode(String.self, forKey: .claim_name) {
            self = .namespacedClaim(NamespacedClaim(namespace: namespace, claimName: claimName))
        } else {
            throw DecodingError.dataCorruptedError(forKey: .path, in: container, debugDescription: "Invalid claim format")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .pathClaim(let claim):
            try container.encode(claim.path, forKey: .path)
        case .namespacedClaim(let claim):
            try container.encode(claim.namespace, forKey: .namespace)
            try container.encode(claim.claimName, forKey: .claim_name)
        }
    }
}

public struct PathClaim: Codable {
    public let path: [String]
    
    public init(path: [String]) {
        self.path = path
    }
}

public struct NamespacedClaim: Codable {
    public let namespace: String
    public let claimName: String
    
    public init(namespace: String, claimName: String) {
        self.namespace = namespace
        self.claimName = claimName
    }
}
