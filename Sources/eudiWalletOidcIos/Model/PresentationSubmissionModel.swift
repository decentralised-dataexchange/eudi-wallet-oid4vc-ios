//
//  PresentationSubmissionModel.swift
//
//
//  Created by Mumthasir mohammed on 13/03/24.
//

import Foundation

// MARK: - PresentationSubmissionModel
struct PresentationSubmissionModel: Codable {
    let id, definitionID: String
    let descriptorMap: [DescriptorMap]
}

// MARK: - DescriptorMap
class DescriptorMap: Codable {
    let id, path: String
    let format: String
    let pathNested: DescriptorMap?

    init(id: String, path: String, format: String, pathNested: DescriptorMap?) {
        self.id = id
        self.path = path
        self.format = format
        self.pathNested = pathNested
    }
}
