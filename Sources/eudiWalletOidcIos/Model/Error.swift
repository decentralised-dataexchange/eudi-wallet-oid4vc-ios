//
//  Error.swift
//
//
//  Created by Mumthasir mohammed on 19/03/24.
//

import Foundation

struct ErrorResponse: Codable {
    var message: String?
    var code: Int?
    
    enum CodingKeys: String, CodingKey {
        case message = "message"
        case code = "code"
    }
}

public struct EUDIError {
    public var message: String?
    public var code: Int?
    
    init(from: ErrorResponse) {
        message = from.message
        code = from.code
    }
}
