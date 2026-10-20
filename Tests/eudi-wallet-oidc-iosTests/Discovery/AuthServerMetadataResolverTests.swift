//
//  AuthServerMetadataResolverTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

final class AuthServerMetadataResolverTests: XCTestCase {

    private let identifier = "https://as.example.com/auth"
    private let oauthInsertion = "/.well-known/oauth-authorization-server/auth"
    private let oidcInsertion = "/.well-known/openid-configuration/auth"
    private let oidcSuffix = "/auth/.well-known/openid-configuration"

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    private var metadata: String {
        """
        {"issuer":"\(identifier)","authorization_endpoint":"\(identifier)/authorize",
         "token_endpoint":"\(identifier)/token","jwks_uri":"\(identifier)/jwks",
         "grant_types_supported":["authorization_code"]}
        """
    }

    private func serve(_ responses: [String: String]) {
        StubURLProtocol.handler = { request in
            let path = request.url?.path ?? ""
            guard let body = responses[path] else {
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data("not found".utf8))
            }
            let response = HTTPURLResponse(
                url: request.url!, statusCode: 200, httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, Data(body.utf8))
        }
    }

    private func httpAllowed(_ policy: DiscoveryPolicy) -> DiscoveryPolicy {
        var policy = policy
        policy.allowedSchemes = ["http", "https"]
        return policy
    }

    private func resolve(policy: DiscoveryPolicy = .standard, input: String? = nil) async -> DiscoveredAuthServerMetadata {
        await AuthServerMetadataResolver(policy: httpAllowed(policy), session: StubURLProtocol.session())
            .resolve(input ?? identifier)
    }

    /// Section 12.2.4 names the oauth-authorization-server location; it must be asked first.
    func testTheRfc8414LocationIsTriedFirst() async {
        serve([oauthInsertion: metadata])
        let result = await resolve()

        XCTAssertNil(result.configuration.error)
        XCTAssertEqual(result.diagnostics.wellKnown, WellKnownURLBuilder.oauthAuthorizationServer)
        XCTAssertFalse(result.diagnostics.usedOpenIdConfigurationFallback)
    }

    /// EBSI's authorization server: oauth-authorization-server 404s, openid-configuration answers.
    func testOpenIdConfigurationAnswersWhenTheRfc8414LocationIsMissing() async {
        serve([oidcSuffix: metadata])
        let result = await resolve()

        XCTAssertNil(result.configuration.error)
        XCTAssertEqual(result.diagnostics.wellKnown, WellKnownURLBuilder.openIdConfiguration)
        XCTAssertTrue(result.diagnostics.usedOpenIdConfigurationFallback)
    }

    func testTheOpenIdConfigurationInsertionFormIsTriedBeforeEitherSuffixForm() async {
        serve([oidcInsertion: metadata])
        let result = await resolve()

        XCTAssertNil(result.configuration.error)
        XCTAssertEqual(result.diagnostics.form, .insertion)
        XCTAssertEqual(result.diagnostics.attemptedURLs.count, 2)
    }

    func testStrictPolicyAsksOnlyTheRfc8414Location() async {
        serve([oidcSuffix: metadata])
        let result = await resolve(policy: .strict)

        XCTAssertNotNil(result.configuration.error)
        XCTAssertEqual(result.diagnostics.attemptedURLs.count, 1)
    }

    func testADocumentWithNoTokenEndpointIsRejected() async {
        serve([oauthInsertion: #"{"issuer":"https://as.example.com/auth"}"#])
        let result = await resolve()
        XCTAssertTrue(result.configuration.error?.message?.contains("token endpoint") == true)
    }

    /// RFC 8414 mandates response_types_supported; OpenID4VCI explicitly allows omitting it.
    func testAPreAuthorizedOnlyServerOmittingResponseTypesIsAccepted() async {
        serve([oauthInsertion: """
        {"issuer":"\(identifier)","token_endpoint":"\(identifier)/token",
         "grant_types_supported":["urn:ietf:params:oauth:grant-type:pre-authorized_code"]}
        """])
        let result = await resolve()
        XCTAssertNil(result.configuration.error)
    }

    /// Hosts pass a full well-known URL; it must be stripped, not appended to.
    func testAFullWellKnownUrlIsAcceptedAsTheIdentifier() async {
        serve([oauthInsertion: metadata])
        let result = await resolve(input: "\(identifier)/.well-known/oauth-authorization-server")

        XCTAssertNil(result.configuration.error)
        XCTAssertEqual(result.diagnostics.identifier, identifier)
    }

    func testABlankAddressReportsAnError() async {
        let result = await AuthServerMetadataResolver().resolve(nil)
        XCTAssertNotNil(result.configuration.error)
    }
}
