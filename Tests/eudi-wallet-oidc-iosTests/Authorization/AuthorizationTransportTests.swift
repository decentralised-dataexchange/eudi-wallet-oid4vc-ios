//
//  AuthorizationTransportTests.swift
//

import XCTest
@testable import eudiWalletOidcIos

/// The four transports and the precedence between them.
///
/// Precedence is the previous implementation's -- interactive extension, PAR, in-app, browser -- and
/// is asserted here because deployed servers are distinguished only by which branch they take.
///
/// Mirrors `AuthorizationTransportTest` in the Android SDK.
final class AuthorizationTransportTests: XCTestCase {

    private struct NoIdToken: IdTokenResponding {
        func respond(
            wallet: WalletIdentity,
            authConfig: AuthorisationServerWellKnownConfiguration,
            location: String
        ) async -> String? { nil }
    }

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    private func authConfig(
        interactive: String? = nil,
        requirePar: Bool = false
    ) -> AuthorisationServerWellKnownConfiguration {
        var config = AuthorisationServerWellKnownConfiguration()
        config.issuer = "https://as.example.com"
        config.authorizationEndpoint = "https://as.example.com/authorize"
        config.tokenEndpoint = "https://as.example.com/token"
        config.pushedAuthorizationRequestEndpoint = "https://as.example.com/par"
        config.interactiveAuthorizationEndpoint = interactive
        config.requirePushedAuthorizationRequests = requirePar
        return config
    }

    private func session(_ config: AuthorisationServerWellKnownConfiguration) -> IssuanceSession {
        IssuanceSession(credentialOffer: nil, issuerConfig: nil, authConfig: config)
    }

    private func resolve(
        _ config: AuthorisationServerWellKnownConfiguration,
        mode: AuthorizationMode = .browser,
        policy: AuthorizationRequestPolicy = .standard
    ) async -> AuthorizationResponse {
        await AuthorizationRequestResolver(policy: policy, idTokenResponder: NoIdToken()).resolve(
            session: session(config),
            wallet: WalletIdentity(did: "did:key:zabc"),
            attestation: nil,
            codeVerifier: String(repeating: "a", count: 64),
            authorizationDetails: "[]",
            selection: CredentialSelection(format: "jwt_vc_json"),
            mode: mode,
            urlSession: StubURLProtocol.session()
        )
    }

    // MARK: - Precedence

    func testTheBrowserTransportIsTheDefault() async {
        let result = await resolve(authConfig())

        XCTAssertEqual(result.outcome, .openInBrowser)
        XCTAssertEqual(result.request?.transport, .browser)
        XCTAssertTrue(result.url?.contains("/authorize?") == true)
    }

    func testParIsUsedWhenTheServerRequiresIt() async {
        StubURLProtocol.respond(
            status: 201,
            body: #"{"request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":90}"#
        )

        let result = await resolve(authConfig(requirePar: true))

        XCTAssertEqual(result.outcome, .openInBrowser)
        XCTAssertEqual(result.request?.transport, .pushed)
        XCTAssertTrue(result.url?.contains("request_uri=urn") == true)
        // the PAR endpoint, not the authorization endpoint: the URL the request actually went to
        XCTAssertEqual(result.request?.endpoint, "https://as.example.com/par")
    }

    func testTheInteractiveExtensionTakesPrecedenceOverPar() async {
        StubURLProtocol.respond(
            body: #"{"status":"ok","type":"redirect_to_web","request_uri":"urn:x"}"#
        )

        let result = await resolve(
            authConfig(interactive: "https://as.example.com/iar", requirePar: true)
        )

        XCTAssertEqual(result.request?.transport, .interactiveAuthorization)
        XCTAssertEqual(result.request?.endpoint, "https://as.example.com/iar")
    }

    func testTheInteractiveExtensionCanBeTurnedOffByPolicy() async {
        let result = await resolve(
            authConfig(interactive: "https://as.example.com/iar"),
            policy: .strict
        )

        XCTAssertEqual(result.outcome, .openInBrowser)
        XCTAssertEqual(result.request?.transport, .browser)
    }

    // MARK: - Outcomes

    func testAPresentationRequestBecomesPresentationRequired() async {
        StubURLProtocol.respond(
            body: #"""
            {"status":"ok","type":"openid4vp_presentation","auth_session":"sess-1",
             "expires_in":120,"openid4vp_request":{"nonce":"n"}}
            """#
        )

        let result = await resolve(authConfig(interactive: "https://as.example.com/iar"))

        XCTAssertEqual(result.outcome, .presentationRequired)
        XCTAssertEqual(result.authSession, "sess-1")
        XCTAssertEqual(result.expiresIn, 120)
        XCTAssertTrue(result.url?.contains("auth_session=sess-1") == true)
        XCTAssertTrue(result.url?.contains("openid4vp_request=") == true)
    }

    /// The OAuth error code used to be lost on every PAR and IAR rejection.
    func testARejectedParKeepsTheOauthErrorCode() async {
        StubURLProtocol.respond(
            status: 400,
            body: #"{"error":"invalid_request","error_description":"redirect_uri is not registered"}"#
        )

        let result = await resolve(authConfig(requirePar: true))

        XCTAssertEqual(result.outcome, .failed)
        XCTAssertEqual(result.error?.errorCode, "invalid_request")
        XCTAssertEqual(result.error?.message, "redirect_uri is not registered")
        XCTAssertEqual(result.error?.httpStatus, 400)
    }

    /// RFC 9126 section 2.2. Received all along, and read by nothing.
    func testTheParRequestUriLifetimeReachesTheCaller() async {
        StubURLProtocol.respond(
            status: 201,
            body: #"{"request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":90}"#
        )

        let result = await resolve(authConfig(requirePar: true))

        XCTAssertEqual(result.expiresIn, 90)
    }

    /// `state` and `redirect_uri` are generated inside the SDK. Without them on the response nothing
    /// can validate the browser callback, and the token request has to guess at a value it is
    /// required to repeat verbatim (RFC 6749 section 4.1.3).
    func testTheResponseReportsWhatWasActuallySent() async {
        let result = await resolve(authConfig())
        let request = result.request

        XCTAssertEqual(request?.state, request?.parameters["state"])
        XCTAssertEqual(request?.redirectUri, request?.parameters["redirect_uri"])
        XCTAssertEqual(request?.nonce, request?.parameters["nonce"])
        XCTAssertEqual(request?.redirectUri, "openid://callback")
    }

    /// Every outcome carries it, failures included -- that is when it is most needed.
    func testAFailureStillReportsWhatWasSent() async {
        StubURLProtocol.respond(status: 400, contentType: "text/plain", body: "nope")

        let result = await resolve(authConfig(requirePar: true))

        XCTAssertEqual(result.outcome, .failed)
        XCTAssertEqual(result.request?.transport, .pushed)
        XCTAssertNotNil(result.request?.parameters["code_challenge"])
    }

    /// A blank `issuer_state` used to go out on every request that had no issuer state, which some
    /// authorization servers reject.
    func testABlankIssuerStateIsOmitted() async {
        let result = await resolve(authConfig())

        XCTAssertNil(result.request?.parameters["issuer_state"])
    }
    // MARK: - Parity with the Android SDK

    /// RFC 7636 section 4.3: the method is meaningless without the challenge. iOS used to put
    /// `code_challenge_method` in the base dictionary, so a blank challenge produced a malformed
    /// PKCE request that Android never sent.
    func testTheCodeChallengeMethodTravelsOnlyWithAChallenge() async {
        let result = await resolve(authConfig())
        let parameters = result.request?.parameters

        if parameters?["code_challenge"] == nil {
            XCTAssertNil(parameters?["code_challenge_method"])
        } else {
            XCTAssertEqual(parameters?["code_challenge_method"], "S256")
        }
    }

    /// The IAR presentation URL is read back by the verification side. `request_uri` is deliberately
    /// absent: Android's VerificationService tests it *before* `openid4vp_request`, so carrying it
    /// would route an IAR presentation to the wrong handler.
    func testTheInteractivePresentationURLMatchesAndroid() async {
        StubURLProtocol.respond(
            body: #"""
            {"status":"ok","type":"openid4vp_presentation","auth_session":"sess-1",
             "request_uri":"urn:should-not-appear","openid4vp_request":{"nonce":"n"}}
            """#
        )

        let result = await resolve(authConfig(interactive: "https://as.example.com/iar"))
        let url = result.url ?? ""

        XCTAssertTrue(url.contains("client_id="))
        XCTAssertTrue(url.contains("status=ok"))
        XCTAssertTrue(url.contains("type=openid4vp_presentation"))
        XCTAssertTrue(url.contains("auth_session=sess-1"))
        XCTAssertTrue(url.contains("openid4vp_request="))
        XCTAssertFalse(url.contains("request_uri="))
    }

    /// The browser hand-off carries only what RFC 9126 section 4 describes. `type` and `status` used
    /// to travel so the wallet could read them back; the typed outcome replaces that round trip.
    func testTheInteractiveBrowserURLCarriesOnlyClientIdAndRequestUri() async {
        StubURLProtocol.respond(
            body: #"{"status":"ok","type":"redirect_to_web","request_uri":"urn:x"}"#
        )

        let result = await resolve(authConfig(interactive: "https://as.example.com/iar"))
        let url = result.url ?? ""

        XCTAssertEqual(result.outcome, .openInBrowser)
        XCTAssertTrue(url.contains("client_id="))
        XCTAssertTrue(url.contains("request_uri=urn"))
        XCTAssertFalse(url.contains("type="))
        XCTAssertFalse(url.contains("status="))
    }

    /// The raw values are Android's enum constant names, so a logged outcome reads the same on both.
    func testTheOutcomeRawValuesMatchAndroid() {
        XCTAssertEqual(AuthorizationOutcome.authorizationCode.rawValue, "AUTHORIZATION_CODE")
        XCTAssertEqual(AuthorizationOutcome.failed.rawValue, "FAILED")
        XCTAssertEqual(AuthorizationTransportKind.interactiveAuthorization.rawValue, "INTERACTIVE_AUTHORIZATION")
        XCTAssertEqual(AuthorizationTransportKind.inApp.rawValue, "IN_APP")
    }

    /// `queryItems` already percent-decodes; decoding a second time mangled any value containing a
    /// percent sign followed by two hex digits.
    func testQueryParametersAreDecodedExactlyOnce() {
        let url = "openid://callback?code=a%2Bb%20c&state=100%25"
        XCTAssertEqual(AuthorizationURI.queryParameter(url, "code"), "a+b c")
        XCTAssertEqual(AuthorizationURI.queryParameter(url, "state"), "100%")
    }
    // MARK: - The interaction type is the discriminator

    /// `type` decides, not the shape of the payload: the wallet advertises
    /// `interaction_types_supported` and the server answers by naming the one it chose. iOS used to
    /// dispatch on the presence of `openid4vp_request`, which made that negotiation pointless.
    func testAnAnnouncedPresentationWithNoRequestIsRefused() async {
        StubURLProtocol.respond(
            body: #"{"status":"ok","type":"openid4vp_presentation","auth_session":"s1"}"#
        )

        let result = await resolve(authConfig(interactive: "https://as.example.com/iar"))

        XCTAssertEqual(result.outcome, .failed)
        XCTAssertTrue(result.error?.message?.contains("no openid4vp_request") == true)
    }

    func testAnAnnouncedRedirectWithNoRequestUriIsRefused() async {
        StubURLProtocol.respond(body: #"{"status":"ok","type":"redirect_to_web"}"#)

        let result = await resolve(authConfig(interactive: "https://as.example.com/iar"))

        XCTAssertEqual(result.outcome, .failed)
        XCTAssertTrue(result.error?.message?.contains("no request_uri") == true)
    }

    /// A payload the wallet could act on does not override a type it did not advertise. This is the
    /// case iOS previously turned into a silent browser hand-off.
    func testAnUnadvertisedTypeIsRefusedEvenWithAUsablePayload() async {
        StubURLProtocol.respond(
            body: #"{"type":"something_new","request_uri":"urn:x","openid4vp_request":{"nonce":"n"}}"#
        )

        let result = await resolve(authConfig(interactive: "https://as.example.com/iar"))

        XCTAssertEqual(result.outcome, .failed)
        XCTAssertTrue(result.error?.message?.contains("does not support: something_new") == true)
    }

    /// An absent type is a broken server, not something to compensate for quietly.
    func testAnAbsentTypeIsRefused() async {
        StubURLProtocol.respond(body: #"{"openid4vp_request":{"nonce":"n"},"auth_session":"s1"}"#)

        let result = await resolve(authConfig(interactive: "https://as.example.com/iar"))

        XCTAssertEqual(result.outcome, .failed)
        XCTAssertTrue(result.error?.message?.contains("does not support: none") == true)
    }
}
