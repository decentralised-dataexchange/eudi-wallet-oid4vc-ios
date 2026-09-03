//
//  IssuerMetadataResolverTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

final class IssuerMetadataResolverTests: XCTestCase {

    private let identifier = "https://issuer.example.com/tenant"
    private let insertionPath = "/.well-known/openid-credential-issuer/tenant"
    private let suffixPath = "/tenant/.well-known/openid-credential-issuer"

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    private func v1Metadata(issuer: String? = nil) -> String {
        """
        {"credential_issuer":"\(issuer ?? identifier)",
         "credential_endpoint":"https://issuer.example.com/credential",
         "credential_configurations_supported":{"PidSdJwt":{"format":"dc+sd-jwt"}}}
        """
    }

    /// The shape the EBSI conformance issuer publishes.
    private func draftMetadata() -> String {
        """
        {"credential_issuer":"\(identifier)",
         "credential_endpoint":"https://issuer.example.com/credential",
         "authorization_server":"https://as.example.com/auth-mock",
         "credentials_supported":[{"format":"jwt_vc","types":["VerifiableCredential"]}]}
        """
    }

    /// Serves only the given paths; anything else 404s, which is how the fallback is exercised.
    private func serve(_ responses: [String: String], contentType: String? = "application/json", status: Int = 200) {
        StubURLProtocol.handler = { request in
            let path = request.url?.path ?? ""
            guard let body = responses[path] else {
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data("not found".utf8))
            }
            var headers: [String: String] = [:]
            if let contentType { headers["Content-Type"] = contentType }
            let response = HTTPURLResponse(
                url: request.url!, statusCode: status, httpVersion: nil, headerFields: headers
            )!
            return (response, Data(body.utf8))
        }
    }

    /// MockWebServer's equivalent speaks http, so every policy under test has to permit it.
    private func httpAllowed(_ policy: DiscoveryPolicy) -> DiscoveryPolicy {
        var policy = policy
        policy.allowedSchemes = ["http", "https"]
        return policy
    }

    private func resolve(
        policy: DiscoveryPolicy = .standard,
        verifier: SignedMetadataVerifier = SignatureValidatorSignedMetadataVerifier()
    ) async -> DiscoveredIssuerMetadata {
        await IssuerMetadataResolver(
            policy: httpAllowed(policy), signedMetadataVerifier: verifier, session: StubURLProtocol.session()
        ).resolve(identifier)
    }

    func testTheSpecInsertionUrlIsTriedFirst() async {
        serve([insertionPath: v1Metadata()])
        let result = await resolve()

        XCTAssertNil(result.configuration.error)
        XCTAssertEqual(result.diagnostics.form, .insertion)
        XCTAssertEqual(result.diagnostics.specVersion, .v1_0)
        XCTAssertFalse(result.diagnostics.usedSuffixFallback)
    }

    /// EBSI's own layout: the spec URL 404s and only the suffix form answers.
    func testA404OnTheSpecUrlFallsBackToTheSuffixUrl() async {
        serve([suffixPath: draftMetadata()])
        let result = await resolve()

        XCTAssertNil(result.configuration.error)
        XCTAssertEqual(result.diagnostics.form, .suffix)
        XCTAssertEqual(result.diagnostics.specVersion, .draft)
        XCTAssertTrue(result.diagnostics.usedSuffixFallback)
        XCTAssertEqual(result.diagnostics.attemptedURLs.count, 2)
    }

    func testStrictPolicyDoesNotTryTheSuffixUrl() async {
        serve([suffixPath: v1Metadata()])
        let result = await resolve(policy: .strict)

        XCTAssertNotNil(result.configuration.error)
        XCTAssertEqual(result.diagnostics.attemptedURLs.count, 1)
    }

    func testStrictPolicyRejectsDraftMetadata() async {
        serve([insertionPath: draftMetadata()])
        let result = await resolve(policy: .strict)
        XCTAssertNotNil(result.configuration.error)
    }

    /// The old implementation reported whichever URL happened to be tried last, so a 403 on the
    /// URL the issuer actually uses was masked by a 404 on the fallback.
    func testADefiniteErrorOutranksA404FromAnotherUrl() async {
        StubURLProtocol.handler = { request in
            let status = request.url?.path == self.insertionPath ? 403 : 404
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
            return (response, Data("nope".utf8))
        }
        let result = await resolve()
        XCTAssertEqual(result.configuration.error?.code, 403)
    }

    // MARK: - Signed metadata

    func testAnUnsignedJwtIsRejectedRatherThanDecoded() async {
        // Header {"alg":"none"}, payload {"credential_issuer":"https://attacker.example.com"}.
        let unsigned = "eyJhbGciOiJub25lIn0."
            + "eyJjcmVkZW50aWFsX2lzc3VlciI6Imh0dHBzOi8vYXR0YWNrZXIuZXhhbXBsZS5jb20ifQ."
        serve([insertionPath: unsigned], contentType: "application/jwt")

        let result = await resolve()

        XCTAssertNotNil(result.configuration.error)
        XCTAssertNil(result.configuration.credentialIssuer)
    }

    /// A JWT mislabelled as JSON must still reach the verifier, never be trusted.
    func testAJwtServedAsJsonIsStillRoutedToTheVerifier() async {
        let unsigned = "eyJhbGciOiJub25lIn0.eyJjcmVkZW50aWFsX2lzc3VlciI6IngifQ.sig"
        serve([insertionPath: unsigned])

        let result = await resolve()
        XCTAssertNotNil(result.configuration.error)
    }

    /// Refusing outright stays available, and is always safe: every issuer must serve JSON too.
    func testTheRejectingVerifierRefusesSignedMetadataOutright() async {
        serve([insertionPath: "eyJhbGciOiJFUzI1NiJ9.e30.sig"], contentType: "application/jwt")

        let result = await resolve(verifier: RejectingSignedMetadataVerifier())

        XCTAssertNotNil(result.configuration.error)
        XCTAssertTrue(result.configuration.error?.message?.contains("cannot verify") == true)
    }

    // MARK: - Documents

    func testADocumentMatchingNoKnownShapeIsRejected() async {
        serve([insertionPath: #"{"something_else":true}"#])
        let result = await resolve()
        XCTAssertTrue(result.configuration.error?.message?.contains("recognisable") == true)
    }

    func testMalformedJsonIsReportedRatherThanSwallowed() async {
        serve([insertionPath: "{ not json"])
        let result = await resolve()
        XCTAssertNotNil(result.configuration.error)
    }

    func testAnOversizedDocumentIsRefused() async {
        serve([insertionPath: v1Metadata()])
        var policy = DiscoveryPolicy.standard
        policy.maxMetadataBytes = 10
        let result = await resolve(policy: policy)
        XCTAssertNotNil(result.configuration.error)
    }

    /// Never a bare nil: a caller's error branch has to have something to fire on.
    func testABlankAddressReportsAnError() async {
        let result = await IssuerMetadataResolver().resolve(nil)
        XCTAssertNotNil(result.configuration.error)
    }

    func testADisallowedSchemeIsRefusedBeforeAnyRequest() async {
        let result = await IssuerMetadataResolver().resolve("file:///etc/passwd")
        XCTAssertTrue(result.configuration.error?.message?.contains("unsupported scheme") == true)
    }
}
