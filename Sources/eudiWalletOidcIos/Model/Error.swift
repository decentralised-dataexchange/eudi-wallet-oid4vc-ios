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

/// A failure, as far as it could be understood.
///
/// `code` is a **legacy sentinel**, not the protocol's error code: it only ever holds `1`
/// ("DID is invalid") or `-1` ("read `message`"), which is why an `Int` was enough. OAuth error
/// codes are strings -- `invalid_grant`, `invalid_proof`, `use_dpop_nonce` -- so they could never
/// fit there and were dropped. New code should branch on `errorCode` and leave `code` to the
/// callers that still switch on it.
///
/// Mirrors `ErrorResponse` in the Android SDK field for field.
public struct EUDIError: Codable {
    public var message: String?
    public var code: Int?

    /// The OAuth 2.0 error code exactly as the server sent it, when it sent one.
    ///
    /// This is the only part of a failure a program can act on: RFC 6749 section 5.2 and
    /// OpenID4VCI section 6.3 define the codes, and a wallet needs them to tell "wrong transaction
    /// code" from "expired offer" without matching on prose that changes per issuer and language.
    public var errorCode: String?

    /// RFC 6749 section 5.2 `error_uri` -- a page describing the error, when the server offers one.
    public var errorUri: String?

    /// The HTTP status the failure arrived with, when a response carried it.
    public var httpStatus: Int?

    /// The unparsed body, kept for diagnostics when none of the known shapes matched.
    public var raw: String?

    init(from: ErrorResponse) {
        message = from.message
        code = from.code
    }

    init(
        message: String?,
        code: Int? = -1,
        errorCode: String? = nil,
        errorUri: String? = nil,
        httpStatus: Int? = nil,
        raw: String? = nil
    ) {
        self.message = message
        self.code = code
        self.errorCode = errorCode
        self.errorUri = errorUri
        self.httpStatus = httpStatus
        self.raw = raw
    }
}
