//
//  PresentationDefinitionModel.swift
//
//
//  Created by Mumthasir mohammed on 13/03/24.
//

import Foundation

// MARK: - PresentationDefinitionModel
public struct PresentationDefinitionModel: Codable {
    public let id: String?
    public let format: [String: JwtVp]?
    public let inputDescriptors: [InputDescriptor]?

    enum CodingKeys: String, CodingKey {
        case id, format
        case inputDescriptors = "input_descriptors"
    }
}

// MARK: - JwtVp
public struct JwtVp: Codable {
    public let alg: [String]?
}

// MARK: - InputDescriptor
public struct InputDescriptor: Codable {
    public var id: String?
    public let name: String?
    public let purpose: String?
    public let constraints: Constraints?
    public let format: InputDescriptorFormat?
}

// MARK: - Constraints
public struct Constraints: Codable {
    public let limitDisclosure: String?
    public let fields: [Field]?
    enum CodingKeys: String, CodingKey {
        case fields
        case limitDisclosure = "limit_disclosure"
    }
}

// MARK: - Field
public struct Field: Codable {
    public let path: [String]?
    public let filter: Filter?
}

// MARK: - Filter
public struct Filter: Codable {
    public let type: String?
    public let contains: Contains?
    public let pattern: String?
}

// MARK: - Contains
public struct Contains: Codable {
    public let const: String?
}

// MARK: - InputDescriptorFormat
public struct InputDescriptorFormat: Codable {
    let jwtVc: JwtVp?

    enum CodingKeys: String, CodingKey {
        case jwtVc = "jwt_vc"
    }
}

