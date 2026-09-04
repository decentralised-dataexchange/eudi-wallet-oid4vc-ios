//
//  AuthorizationResponseTests.swift
//

import XCTest
@testable import eudiWalletOidcIos

/// The response object's own contract.
///
/// Two things are pinned here. First, that each factory sets exactly the properties its outcome
/// documents -- the type's own documentation carries that table, and a reader has to be able to
/// trust it. Second, that `location` still holds what the deprecated `processAuthorisationRequest`
/// returns, because callers that have not migrated parse `code` and `error` back out of it.
///
/// Mirrors `AuthorizationResponseTest` in the Android SDK.
final class AuthorizationResponseTests: XCTestCase {

    /// Mirrors the flattening the deprecated entry point performs.
    private func asDeprecatedString(_ response: AuthorizationResponse) -> String? {
        switch response.outcome {
        case .authorizationCode: return response.location
        case .openInBrowser, .presentationRequired, .idTokenRequired: return response.url
        case .failed: return response.location
        }
    }

    func testAnAuthorizationCodeCarriesTheCodeStateAndRedirect() {
        let response = AuthorizationResponse.authorizationCode(
            code: "abc123",
            state: "xyz",
            location: "openid://callback?code=abc123&state=xyz"
        )

        XCTAssertEqual(response.outcome, .authorizationCode)
        XCTAssertEqual(response.code, "abc123")
        XCTAssertEqual(response.state, "xyz")
        XCTAssertNil(response.url)
        XCTAssertNil(response.error)
        XCTAssertEqual(asDeprecatedString(response), "openid://callback?code=abc123&state=xyz")
    }

    func testABrowserHandOffCarriesTheURLAndLifetime() {
        let response = AuthorizationResponse.openInBrowser(url: "https://as.example/authorize?x=1", expiresIn: 90)

        XCTAssertEqual(response.outcome, .openInBrowser)
        XCTAssertEqual(response.expiresIn, 90)
        XCTAssertNil(response.code)
        XCTAssertEqual(asDeprecatedString(response), "https://as.example/authorize?x=1")
    }

    func testAPresentationRequestCarriesTheAuthSession() {
        let response = AuthorizationResponse.presentationRequired(
            url: "https://as.example/authorize?auth_session=s1",
            authSession: "s1",
            expiresIn: 120
        )

        XCTAssertEqual(response.outcome, .presentationRequired)
        XCTAssertEqual(response.authSession, "s1")
        XCTAssertEqual(response.expiresIn, 120)
        XCTAssertNil(response.code)
    }

    /// A failure with no redirect flattens to nil, exactly as the previous implementation did -- the
    /// compatibility shim must not start returning strings where it returned nil.
    func testAFailureWithoutARedirectFlattensToNil() {
        let response = AuthorizationResponse.failed(reason: "refused", httpStatus: 400)

        XCTAssertEqual(response.outcome, .failed)
        XCTAssertEqual(response.error?.httpStatus, 400)
        XCTAssertNil(asDeprecatedString(response))
    }

    func testAFailureReadOffARedirectKeepsIt() {
        let location = "openid://callback?error=access_denied&error_description=nope"
        let response = AuthorizationResponse.failed(
            reason: "nope",
            errorCode: "access_denied",
            location: location
        )

        XCTAssertEqual(response.error?.errorCode, "access_denied")
        XCTAssertEqual(asDeprecatedString(response), location)
    }
}
