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
    public let name: String?
    public let purpose: String?
    public let format: [String: JwtVp]?
    public var inputDescriptors: [InputDescriptor]?
    public var docType: String?
    enum CodingKeys: String, CodingKey {
        case id, format, name, purpose
        case inputDescriptors = "input_descriptors"
        case docType = "doc_type"
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
    public var constraints: Constraints?
    public let format: [String: JwtVp?]?//InputDescriptorFormat?
}
// MARK: - Constraints
public struct Constraints: Codable {
    public let limitDisclosure: String?
    public var fields: [Field]?
    enum CodingKeys: String, CodingKey {
        case fields
        case limitDisclosure = "limit_disclosure"
    }
}
// MARK: - Field
public struct Field: Codable {
    public var path: [String]?
    public let filter: Filter?
}
// MARK: - Filter
public struct Filter: Codable {
    public let type: String?
    public let contains: Contains?
    public let const: StringOrBool?
    public let pattern: String?
    public let enumValues: [String]?   // renamed to avoid keyword conflict

    enum CodingKeys: String, CodingKey {
        case type
        case contains
        case const
        case pattern
        case enumValues = "enum"       // map JSON "enum" → Swift enumValues
    }
}
// MARK: - Contains
public struct Contains: Codable {
    public let const: String?
    public let pattern: String?
}
// MARK: - InputDescriptorFormat
public struct InputDescriptorFormat: Codable {
    let jwtVc: JwtVp?
    enum CodingKeys: String, CodingKey {
        case jwtVc = "jwt_vc"
    }
}

public enum StringOrBool: Codable {
    case string(String)
    case bool(Bool)
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let boolValue = try? container.decode(Bool.self) {
            self = .bool(boolValue)
        } else if let stringValue = try? container.decode(String.self) {
            self = .string(stringValue)
        } else {
            throw DecodingError.typeMismatch(
                StringOrBool.self,
                DecodingError.Context(codingPath: decoder.codingPath,
                                      debugDescription: "Expected String or Bool for const")
            )
        }
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value):
            try container.encode(value)
        case .bool(let value):
            try container.encode(value)
        }
    }
}
