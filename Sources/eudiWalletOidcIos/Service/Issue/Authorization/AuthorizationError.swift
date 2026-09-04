//
//  AuthorizationError.swift
//
//  Why an authorization request could not be completed.
//

import Foundation

/// Why an authorization request could not be completed.
///
/// Internal to the package: the resolver turns these into an ``AuthorizationResponse`` whose
/// outcome is ``AuthorizationOutcome/failed``, so a caller never has to catch anything.
///
/// Mirrors `AuthorizationException` in the Android SDK.
enum AuthorizationError: Error {

    /// The authorization server metadata named no authorization endpoint.
    case noAuthorizationEndpoint

    /// The request reached the server and was refused.
    ///
    /// The body is read through ``ErrorHandler``, so a rejection carrying
    /// `{"error":"invalid_request","error_description":"..."}` keeps the OAuth code instead of
    /// putting the whole blob in the message.
    case rejected(status: Int?, body: Data?, contentType: String?)

    /// The request never completed -- network, DNS, timeout.
    ///
    /// `failingURL` is `NSErrorFailingURLKey` from the underlying error. It matters: a redirect to a
    /// custom scheme such as `openid://callback` cannot be loaded, so the request "fails" and the
    /// URL it failed on *is* the callback the flow needs.
    case requestFailed(detail: String?, failingURL: String?)

    /// The server answered, but with something this wallet cannot act on.
    ///
    /// The IAR extension's unknown `type` lands here, as does a response with no redirect at all --
    /// both of which used to end in a silent `WrappedResponse(data: nil, error: nil)`.
    case unusable(String, status: Int? = nil)

    /// The same error shape the rest of the SDK returns.
    var asEUDIError: EUDIError {
        switch self {
        case .noAuthorizationEndpoint:
            return EUDIError(message: "This issuer's authorization server could not be identified")

        case let .rejected(status, body, contentType):
            let parsed = ErrorHandler.processError(data: body, contentType: contentType, httpStatus: status)
            let fallback = "The authorization request was refused"
                + (status.map { " (HTTP \($0))" } ?? "")
            return EUDIError(
                message: parsed?.message?.isEmpty == false ? parsed?.message : fallback,
                code: parsed?.code ?? -1,
                errorCode: parsed?.errorCode,
                errorUri: parsed?.errorUri,
                httpStatus: status,
                raw: parsed?.raw
            )

        case let .requestFailed(detail, _):
            return EUDIError(message: detail?.isEmpty == false ? detail : "The authorization request failed")

        case let .unusable(detail, status):
            return EUDIError(message: detail, code: -1, httpStatus: status)
        }
    }
}
