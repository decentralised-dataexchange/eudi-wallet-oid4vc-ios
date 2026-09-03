//
//  CredentialOfferResolverTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

final class CredentialOfferResolverTests: XCTestCase {

    private let issuer = "https://issuer.example.com"

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    private func v1Offer(ids: String = "[\"PidSdJwt\"]") -> String {
        """
        {"credential_issuer":"\(issuer)","credential_configuration_ids":\(ids),
         "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":
           {"pre-authorized_code":"abc","tx_code":{}}}}
        """
    }

    /// The shape the EBSI conformance issuer publishes.
    private func draftOffer() -> String {
        """
        {"credential_issuer":"\(issuer)","credentials":[
          {"format":"jwt_vc","types":["VerifiableCredential","VerifiableAttestation"],
           "trust_framework":{"name":"ebsi"}}]}
        """
    }

    private func link(_ offer: String) -> String {
        "openid-credential-offer://?credential_offer="
            + offer.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    }

    private func resolve(
        _ data: String?,
        policy: CredentialOfferPolicy = .standard,
        session: URLSession? = nil
    ) async -> CredentialOffer {
        let resolver = session.map { CredentialOfferResolver(policy: policy, session: $0) }
            ?? CredentialOfferResolver(policy: policy)
        return await resolver.resolve(data)
    }

    // MARK: - Sources

    func testResolvesAnInlineOffer() async {
        let offer = await resolve(link(v1Offer()))
        XCTAssertNil(offer.error)
        XCTAssertEqual(offer.credentialIssuer, issuer)
        XCTAssertEqual(offer.version, "v2")
    }

    func testResolvesARemoteOffer() async {
        StubURLProtocol.respond(body: v1Offer())
        let offer = await resolve(
            "openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offer/1",
            session: StubURLProtocol.session()
        )
        XCTAssertNil(offer.error)
        XCTAssertEqual(offer.credentialIssuer, issuer)
    }

    /// Section 4.1: the two parameters MUST NOT both be present.
    func testRejectsAnOfferCarryingBothMechanisms() async {
        let data = "openid://?credential_offer=%7B%7D&credential_offer_uri=https://x.example.com/o"
        let offer = await resolve(data)
        XCTAssertTrue(offer.error?.message?.contains("both") == true)
    }

    func testRejectsDataCarryingNoOffer() async {
        let unknown = await resolve("openid://?something_else=1")
        let empty = await resolve("")
        let none = await resolve(nil)
        XCTAssertNotNil(unknown.error)
        XCTAssertNotNil(empty.error)
        XCTAssertNotNil(none.error)
    }

    /// The pre-OpenID4VCI EBSI link, spread across query parameters.
    func testResolvesAnInitiateIssuanceLink() async {
        let data = "openid://initiate_issuance?issuer=" + issuer
            + "&credential_type=VerifiableAttestation&pre-authorized_code=xyz&user_pin_required=true"
        let offer = await resolve(data)
        XCTAssertNil(offer.error)
        XCTAssertEqual(offer.credentialIssuer, issuer)
        XCTAssertEqual(offer.version, "v1")
        XCTAssertEqual(offer.grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode?.preAuthorizedCode, "xyz")
    }

    // MARK: - Policy

    func testRejectsADisallowedSchemeBeforeFetching() async {
        let offer = await resolve("openid://?credential_offer_uri=file:///etc/passwd")
        XCTAssertTrue(offer.error?.message?.contains("unsupported scheme") == true)
    }

    func testHttpIsAllowedByDefaultAndRefusedUnderStrict() async {
        StubURLProtocol.respond(body: v1Offer())
        let data = "openid://?credential_offer_uri=http://localhost:8080/offer"

        let allowed = await resolve(data, session: StubURLProtocol.session())
        XCTAssertNil(allowed.error)

        let strict = await resolve(data, policy: .strict, session: StubURLProtocol.session())
        XCTAssertTrue(strict.error?.message?.contains("unsupported scheme") == true)
    }

    func testNonJsonContentTypePassesByDefaultAndFailsUnderStrict() async {
        StubURLProtocol.respond(contentType: "text/plain", body: v1Offer())
        let data = "openid://?credential_offer_uri=https://issuer.example.com/offer"

        let permissive = await resolve(data, session: StubURLProtocol.session())
        XCTAssertNil(permissive.error)

        StubURLProtocol.respond(contentType: "text/plain", body: v1Offer())
        let strict = await resolve(data, policy: .strict, session: StubURLProtocol.session())
        XCTAssertNotNil(strict.error)
    }

    func testReportsAnHttpFailure() async {
        StubURLProtocol.respond(status: 404, body: "not found")
        let offer = await resolve(
            "openid://?credential_offer_uri=https://issuer.example.com/offer",
            session: StubURLProtocol.session()
        )
        XCTAssertNotNil(offer.error)
        XCTAssertEqual(offer.error?.code, 404)
    }

    /// Section 4.1.3: "The Credential Offer cannot be signed and MUST NOT use application/jwt."
    func testRejectsASignedOffer() async {
        StubURLProtocol.respond(contentType: "application/jwt", body: "eyJhbGciOiJub25lIn0.eyJhIjoxfQ.")
        let offer = await resolve(
            "openid://?credential_offer_uri=https://issuer.example.com/offer",
            session: StubURLProtocol.session()
        )
        XCTAssertTrue(offer.error?.message?.contains("Signed credential offers") == true)
    }

    func testRejectsAJwtServedAsJson() async {
        StubURLProtocol.respond(body: "eyJhbGciOiJub25lIn0.eyJhIjoxfQ.abc")
        let offer = await resolve(
            "openid://?credential_offer_uri=https://issuer.example.com/offer",
            session: StubURLProtocol.session()
        )
        XCTAssertTrue(offer.error?.message?.contains("Signed credential offers") == true)
    }

    // MARK: - Parser selection

    func testResolvesADraftOffer() async {
        let offer = await resolve(link(draftOffer()))
        XCTAssertNil(offer.error)
        XCTAssertEqual(offer.version, "v1")
    }

    func testDraftOffersAreRefusedUnderStrict() async {
        let offer = await resolve(link(draftOffer()), policy: .strict)
        XCTAssertNotNil(offer.error)
    }

    /// Regression: the previous implementation tested `credentials` first, so a document carrying
    /// both shapes was read as a draft and its 1.0 configuration ids were discarded.
    func testOneZeroWinsOverDraftOnADualShapedOffer() async {
        let dual = """
        {"credential_issuer":"\(issuer)",
         "credential_configuration_ids":["PidSdJwt"],
         "credentials":[{"format":"jwt_vc","types":["VerifiableCredential"]}]}
        """
        let offer = await resolve(link(dual))
        XCTAssertNil(offer.error)
        XCTAssertEqual(offer.version, "v2")
        XCTAssertEqual(offer.credentials?.first?.types?.first, "PidSdJwt")
    }

    func testRejectsMalformedJson() async {
        let offer = await resolve("openid://?credential_offer=%7B%20not%20json")
        XCTAssertNotNil(offer.error)
    }

    /// `{}` used to parse "successfully" and fail much later with no useful message.
    func testRejectsAnEmptyObject() async {
        let offer = await resolve("openid://?credential_offer=%7B%7D")
        XCTAssertNotNil(offer.error)
    }
}
