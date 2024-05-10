//
//  PresentationDefinitionModel.swift
//
//
//  Created by Mumthasir mohammed on 13/03/24.
//

import Foundation

// MARK: - PresentationDefinitionModel
public struct PresentationDefinitionModel: Codable {
    let id: String?
    let format: [String: JwtVp]?
    let inputDescriptors: [InputDescriptor]?

    enum CodingKeys: String, CodingKey {
        case id, format
        case inputDescriptors = "input_descriptors"
    }
}

// MARK: - PresentationDefinitionModelFormat
struct PresentationDefinitionModelFormat: Codable {
    let jwtVc, jwtVp: JwtVp?

    enum CodingKeys: String, CodingKey {
        case jwtVc = "jwt_vc"
        case jwtVp = "jwt_vp"
    }
}

// MARK: - JwtVp
struct JwtVp: Codable {
    let alg: [String]?
}

// MARK: - InputDescriptor
struct InputDescriptor: Codable {
    var id: String?
    let name: String?
    let purpose: String?
    let constraints: Constraints?
    let format: InputDescriptorFormat?
}

// MARK: - Constraints
struct Constraints: Codable {
    let fields: [Field]?
}

// MARK: - Field
struct Field: Codable {
    let path: [String]?
    let filter: Filter?
}

// MARK: - Filter
struct Filter: Codable {
    let type: String?
    let contains: Contains?
}

// MARK: - Contains
struct Contains: Codable {
    let const: String?
}

// MARK: - InputDescriptorFormat
struct InputDescriptorFormat: Codable {
    let jwtVc: JwtVp?

    enum CodingKeys: String, CodingKey {
        case jwtVc = "jwt_vc"
    }
}

