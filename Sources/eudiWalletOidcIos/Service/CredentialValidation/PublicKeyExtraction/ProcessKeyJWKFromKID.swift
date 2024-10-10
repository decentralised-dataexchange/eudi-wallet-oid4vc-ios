//
//  File.swift
//
//
//  Created by oem on 10/10/24.
//

import Foundation

class ProcessKeyJWKFromKID {
    static func processJWKfromKid(did: String?) -> [String: Any] {
        guard let did = did else { return [:]}
        let components = did.split(separator: "#")
        guard let didPart = components.first else {
            return [:]
        }
        return DidService.shared.createJWKfromDID(did: String(didPart))
    }
}
