//
//  AuthorizationResponse.swift
//
//  The result of an authorization request.
//

import Foundation

/// The result of an authorization request.
///
/// ``outcome`` says which case this is; every other property is documented with the outcome that
/// fills it, and is `nil` otherwise. Encodes to JSON as-is, so it can be logged verbatim.
///
/// | outcome                | properties set              |
/// |------------------------|-----------------------------|
/// | authorizationCode      | code, state                 |
/// | openInBrowser          | url, expiresIn              |
/// | presentationRequired   | url, authSession, expiresIn |
/// | idTokenRequired        | url                         |
/// | failed                 | error                       |
///
/// ``request`` is set on every outcome, including failures.
///
/// Mirrors `AuthorizationResponse` in the Android SDK property for property. Replaces a
/// `WrappedResponse` whose `data: String?` meant six different things and left the caller
/// re-parsing query parameters off a URL to work out which.
public struct AuthorizationResponse {

    /// Which case this is. Switch on this first; nothing else is meaningful without it.
    public var outcome: AuthorizationOutcome

    /// The OAuth 2.0 authorization code, to be exchanged at the token endpoint.
    ///
    /// Set only when ``outcome`` is ``AuthorizationOutcome/authorizationCode``.
    /// Example: `"SplxlOBeZQQYbYS6WxSbIA"`.
    public var code: String?

    /// The `state` the authorization server echoed back -- compare it against
    /// ``AuthorizationRequestInfo/state`` before spending ``code``.
    ///
    /// Set only with ``AuthorizationOutcome/authorizationCode``, and only when the SDK itself saw
    /// the redirect. On the browser hand-off the callback arrives at the app instead, so the app
    /// makes that comparison.
    public var state: String?

    /// The URL to act on. What to *do* with it is given by ``outcome``:
    ///
    /// - ``AuthorizationOutcome/openInBrowser`` -- open in a browser, not a web view (RFC 8252), so
    ///   the authorization server's session cookie lands in the browser.
    /// - ``AuthorizationOutcome/presentationRequired`` -- an OpenID4VP request the issuer wants
    ///   satisfied before it will authorize (the BankID SUA case). Pass unchanged to
    ///   `VerificationService.processAuthorisationRequest(data:)`.
    /// - ``AuthorizationOutcome/idTokenRequired`` -- the request to answer, carrying
    ///   `response_type=id_token` and the `redirect_uri` to post to.
    ///
    /// `nil` for ``AuthorizationOutcome/authorizationCode`` and ``AuthorizationOutcome/failed``.
    public var url: String?

    /// The IAR profile's opaque session handle, echoed back on the presentation response so the
    /// issuer can rejoin the interrupted authorization.
    ///
    /// Set only on the IAR presentation path; `nil` for a plain OpenID4VP redirect, which has no
    /// such handle. Treat it as opaque -- do not parse it.
    public var authSession: String?

    /// How long the hand-off stays valid, **in seconds** -- the PAR `request_uri` lifetime
    /// (RFC 9126 section 2.2) or the IAR session lifetime. `nil` when the server did not say.
    ///
    /// Example: `90`. A duration, never an absolute timestamp.
    public var expiresIn: Int?

    /// Why it failed. Set only when ``outcome`` is ``AuthorizationOutcome/failed``, and never `nil`
    /// when it is.
    ///
    /// The same ``EUDIError`` the token and credential steps return, so one error shape covers the
    /// whole SDK: `errorCode` is the OAuth code to branch on, `message` the text to show a user,
    /// `httpStatus` and `raw` for logs.
    public var error: EUDIError?

    /// What was sent, and what the caller must carry forward. Set on every outcome.
    public var request: AuthorizationRequestInfo?

    /// The raw redirect the outcome was read from, when there was one.
    ///
    /// Only the deprecated `IssueService.processAuthorisationRequest` needs this: it returns a URL,
    /// and callers that have not migrated still parse `code` and `error` back out of it. New code
    /// reads ``code``, ``state`` and ``error`` instead and can ignore this entirely.
    public var location: String?

    // MARK: - Factories
    //
    // Construction goes through these so no caller can assemble a combination the outcome table
    // does not allow.

    /// The authorization server returned a code; the flow can go on to the token request.
    public static func authorizationCode(
        code: String,
        state: String? = nil,
        location: String? = nil
    ) -> AuthorizationResponse {
        AuthorizationResponse(outcome: .authorizationCode, code: code, state: state, location: location)
    }

    /// The user has to complete authorization in a browser.
    public static func openInBrowser(url: String, expiresIn: Int? = nil) -> AuthorizationResponse {
        AuthorizationResponse(outcome: .openInBrowser, url: url, expiresIn: expiresIn, location: url)
    }

    /// The authorization server wants a presentation before it will authorize.
    public static func presentationRequired(
        url: String,
        authSession: String? = nil,
        expiresIn: Int? = nil
    ) -> AuthorizationResponse {
        AuthorizationResponse(
            outcome: .presentationRequired,
            url: url,
            authSession: authSession,
            expiresIn: expiresIn,
            location: url
        )
    }

    /// The authorization server asked for an ID token instead.
    public static func idTokenRequired(url: String) -> AuthorizationResponse {
        AuthorizationResponse(outcome: .idTokenRequired, url: url, location: url)
    }

    /// The request failed.
    ///
    /// Every path that used to return `WrappedResponse(data: nil, error: nil)` lands here with a
    /// reason.
    public static func failed(_ error: EUDIError, location: String? = nil) -> AuthorizationResponse {
        AuthorizationResponse(outcome: .failed, error: error, location: location)
    }

    /// As ``failed(_:location:)``, for the paths that have only a message.
    public static func failed(
        reason: String,
        errorCode: String? = nil,
        httpStatus: Int? = nil,
        location: String? = nil
    ) -> AuthorizationResponse {
        failed(
            EUDIError(message: reason, code: -1, errorCode: errorCode, httpStatus: httpStatus),
            location: location
        )
    }

    /// Returns a copy carrying ``request``. The resolver builds it once and attaches it to whatever
    /// the transport produced.
    public func with(request: AuthorizationRequestInfo) -> AuthorizationResponse {
        var copy = self
        copy.request = request
        return copy
    }
}

/// The five things an authorization request can produce. Exhaustive.
/// The raw values are the Android enum's constant names, so an outcome logged or transmitted from
/// either platform reads the same.
public enum AuthorizationOutcome: String {
    case authorizationCode = "AUTHORIZATION_CODE"
    case openInBrowser = "OPEN_IN_BROWSER"
    case presentationRequired = "PRESENTATION_REQUIRED"
    case idTokenRequired = "ID_TOKEN_REQUIRED"
    case failed = "FAILED"
}

/// What the authorization request actually sent.
///
/// Not only diagnostics: ``redirectUri`` and ``state`` are needed to finish the flow correctly, and
/// the rest is what makes a server's rejection explicable. A server answering
/// `{"detail":"issuer state is not found"}` is objecting to a parameter, and the outcome alone does
/// not say which.
public struct AuthorizationRequestInfo {

    /// Which transport ran. Three of the four can produce ``AuthorizationOutcome/openInBrowser``;
    /// this says which did.
    public var transport: AuthorizationTransportKind

    /// The URL the request was actually sent to -- the PAR endpoint, the IAR endpoint, or the
    /// authorization endpoint -- rather than whichever one the metadata happened to declare.
    public var endpoint: String?

    /// The `redirect_uri` that was sent. **The token request must repeat this value verbatim**
    /// (RFC 6749 section 4.1.3); a different one is rejected. Do not re-derive it.
    public var redirectUri: String

    /// The `state` that was sent. **Compare the callback's `state` against this** before spending
    /// the code; a mismatch means the callback is not the answer to this request.
    public var state: String

    /// The `nonce` that was sent.
    public var nonce: String

    /// Whether `OAuth-Client-Attestation` headers were attached -- not whether the server accepted
    /// them. `false` means none were available to send.
    public var sentWalletAttestation: Bool = false

    /// Every parameter as it went on the wire, blanks already omitted. For logs and bug reports.
    public var parameters: [String: String] = [:]
}

/// The four ways this SDK can make an authorization request, in the order they are tried.
public enum AuthorizationTransportKind: String {

    /// The IAR profile extension.
    ///
    /// `interactive_authorization_endpoint` appears in no released specification -- not OpenID4VCI,
    /// not RFC 8414, not OpenID Connect Discovery. It is a profile extension, and it is required.
    case interactiveAuthorization = "INTERACTIVE_AUTHORIZATION"

    /// RFC 9126 Pushed Authorization Request.
    case pushed = "PUSHED"

    /// The wallet makes the request itself and follows the redirects. First-party flows only.
    case inApp = "IN_APP"

    /// A URL for the system browser. The default for a scanned offer.
    case browser = "BROWSER"
}
