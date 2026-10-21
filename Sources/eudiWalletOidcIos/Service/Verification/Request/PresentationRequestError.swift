//
//  PresentationRequestError.swift
//  eudiWalletOidcIos
//

import Foundation

/// Why a presentation request could not be resolved.
///
/// Every failure carries a description meant for a user, because integrators show
/// `EUDIError.message` verbatim. `code` fills `EUDIError.code` when the SDK has a code for the
/// failure, and `oauthError` fills `EUDIError.errorCode` when OAuth 2.0 names one.
enum PresentationRequestError: Error {

    /// The scanned data carried none of the parameters that identify a presentation request.
    case noRequest

    /// Both `request` and `request_uri` present. RFC 9101 section 5 forbids this.
    case ambiguousRequest

    /// The `request_uri` fetch failed; carries the verifier's error, or the transport's.
    case fetchFailed(EUDIError)

    /// The `request_uri` answered with an empty body.
    case emptyResponse

    /// The request, or the request object inside it, could not be parsed.
    case malformed(String)

    /// OpenID4VP 1.0 section 5.10.1: a request object fetched by POST does not echo the
    /// `wallet_nonce` the wallet sent, or was encrypted to a key the wallet does not hold.
    case nonceMismatch

    /// The request object carries no signature and the client identifier prefix is not
    /// `redirect_uri`, the only prefix OpenID4VP 1.0 section 5.9 allows unsigned.
    case unsignedRequestObject

    /// The request broke the rules of its client identifier prefix (OpenID4VP 1.0 section 5.9.3),
    /// so the verifier is not who the client_id says. Section 8.5 files this under invalid_request.
    case clientNotVerified(String)

    /// Section 8.5: "The Wallet does not support the Client Identifier Prefix passed in the
    /// Authorization Request."
    case unsupportedClientIdPrefix(String)

    /// OpenID4VP 1.0 section 5.10.1: "The Client Identifier value in the client_id Authorization
    /// Request parameter and the Request Object client_id claim value MUST be identical, including
    /// the Client Identifier Prefix." RFC 9101 section 5 says the same.
    case clientIdMismatch(fromUri: String, fromRequestObject: String)

    /// The `dcql_query` is not valid JSON or breaks OpenID4VP 1.0 section 6.
    case invalidDcqlQuery(String)

    /// A draft `presentation_definition_uri` could not be fetched or did not parse.
    case presentationDefinitionUnavailable(String?)

    /// A draft request arrived while `PresentationRequestPolicy.allowDraftRequests` is false.
    case draftNotAllowed

    /// RFC 6749 section 4.1.2.1.
    static let invalidRequest = "invalid_request"

    var message: String {
        switch self {
        case .noRequest: return "This QR code does not contain a presentation request"
        case .ambiguousRequest: return "The presentation request is invalid: it carries both request and request_uri"
        case .fetchFailed(let error): return error.message ?? "Unable to process request"
        case .emptyResponse: return "Response is null or empty."
        case .malformed(let detail): return detail
        case .nonceMismatch, .unsignedRequestObject: return "Request validation failed"
        case .clientNotVerified(let detail): return "The verifier could not be authenticated: \(detail)"
        case .unsupportedClientIdPrefix(let prefix): return "The client identifier prefix '\(prefix)' is not supported"
        case .clientIdMismatch: return "The client_id in the request does not match the request object"
        case .invalidDcqlQuery(let reason): return "Invalid DCQL query: \(reason)"
        case .presentationDefinitionUnavailable(let detail):
            let suffix = detail.flatMap { $0.isEmpty ? nil : ": \($0)" } ?? ""
            return "The presentation definition could not be fetched\(suffix)"
        case .draftNotAllowed: return "This presentation request uses a draft format that is not supported"
        }
    }

    var eudiError: EUDIError {
        switch self {
        case .fetchFailed(let error):
            return error
        case .invalidDcqlQuery:
            return EUDIError(message: message, code: ErrorCodes.invalidDcqlQuery)
        case .ambiguousRequest, .clientIdMismatch, .clientNotVerified, .unsupportedClientIdPrefix:
            return EUDIError(message: message, code: nil, errorCode: Self.invalidRequest)
        default:
            return EUDIError(message: message, code: nil)
        }
    }
}
