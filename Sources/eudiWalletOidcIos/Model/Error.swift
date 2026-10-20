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
    /// The OAuth `error` code of a JSON error body, when the body has one.
    var errorCode: String?
    
    enum CodingKeys: String, CodingKey {
        case message = "message"
        case code = "code"
        case errorCode = "error_code"
    }
}

public struct EUDIError: Codable {
    public var message: String?
    public var code: Int?
    /// The OAuth `error` code (RFC 6749 section 5.2) of a JSON error body, such as
    /// `invalid_token` or `credential_request_denied`. Nil when the body carries none.
    /// `message` keeps the description, so a wallet can classify by code and show the text.
    public var errorCode: String?
    
    init(from: ErrorResponse) {
        message = from.message
        code = from.code
        errorCode = from.errorCode
    }
}
