//
//  ServerTrustMechanismModels.swift
//  eudiWalletOidcIos
//
//  Codable payload models for the OWS Trust List backend (open lookup endpoint) used by
//  `ServerTrustMechanismService`. iOS counterpart of the Android SDK's TrustList models.
//
//  Endpoint: POST {baseURL}/trust-list/lookup  -> lookup by x5c / kid / did / jwksUri.
//

import Foundation

/// Lookup body — send the identifier the verifier/issuer is known by. Exactly one is populated.
public struct TrustListLookupRequest: Codable {
    public var x5c: [String]?
    public var kid: String?
    public var did: String?
    public var jwksUri: String?

    public init(x5c: [String]? = nil, kid: String? = nil, did: String? = nil, jwksUri: String? = nil) {
        self.x5c = x5c
        self.kid = kid
        self.did = did
        self.jwksUri = jwksUri
    }
}

public struct TrustListLookupResponse: Codable {
    public let match: Bool
    public let entry: TrustListEntry?
}

public struct TrustListEntry: Codable {
    public let status: String?
    public let provider: TrustListProvider?
    public let service: TrustListServiceInfo?
    public let matchType: String?
    public let searchValue: String?
    public let certificateValid: Bool?
    public let certificateDetails: [TrustListCertDetail]?
    public let matchedCertIndex: Int?
    /// The specific trust list this entry matched — used to filter against DCQL `trusted_authorities`.
    public let trustList: TrustListInfo?
}

public struct TrustListInfo: Codable {
    public let name: String?
    public let url: String?
    public let schemeName: String?
}

public struct TrustListProvider: Codable {
    public let tSPName: String?
    public let tSPTradeName: String?
    public let streetAddress: String?
    public let locality: String?
    public let postalCode: String?
    public let countryName: String?
    public let electronicAddress: String?
    public let tSPInformationURI: String?
}

public struct TrustListServiceInfo: Codable {
    public let serviceTypeIdentifier: String?
    public let serviceStatus: String?
    public let statusStartingTime: String?
    public let serviceName: String?
    public let did: String?
    public let kid: String?
    public let jwksURI: String?
    /// Legacy: some responses may still return the cert chain here.
    public let digitalIdentity: [String]?
}

public struct TrustListCertDetail: Codable {
    public let subjectKeyIdentifier: String?
    public let sha256Fingerprint: String?
}
