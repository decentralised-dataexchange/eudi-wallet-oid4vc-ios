//
//  ClientIdentifierVerifierTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
import CryptoKit
import Security
@testable import eudiWalletOidcIos

/// One test or more per row of the leg 2 case matrix (VERIFICATION_REVAMP_PLAN_IOS.md), named
/// after it. The x509 rows use the fixed certificates in `CertificateFixtures`; the DID and
/// attestation rows use `did:jwk`, so nothing goes to the network.
final class ClientIdentifierVerifierTests: XCTestCase {

    // MARK: Fixtures

    private typealias Cert = CertificateFixtures

    private let host = "verifier.example.com"
    private let responseUri = "https://verifier.example.com/response"

    private static func jwk(_ key: P256.Signing.PublicKey) -> [String: Any] {
        let raw = key.rawRepresentation
        return ["kty": "EC", "crv": "P-256", "x": raw.prefix(32).b64url, "y": raw.suffix(32).b64url]
    }

    private static func didJwk(_ key: P256.Signing.PublicKey) -> String {
        "did:jwk:" + (try! JSONSerialization.data(withJSONObject: jwk(key), options: [.sortedKeys])).b64url
    }

    private static func sign(_ header: [String: Any], _ claims: [String: Any], with key: P256.Signing.PrivateKey) -> String {
        var header = header
        header["alg"] = header["alg"] ?? "ES256"
        let input = (try! JSONSerialization.data(withJSONObject: header)).b64url + "."
            + (try! JSONSerialization.data(withJSONObject: claims)).b64url
        let signature = try! key.signature(for: Data(input.utf8)).rawRepresentation.b64url
        return input + "." + signature
    }

    private func claims(_ clientId: String?, extra: [String: Any] = [:]) -> [String: Any] {
        var claims: [String: Any] = ["response_type": "vp_token", "response_mode": "direct_post", "nonce": "n-1",
                                     "state": "s-1", "response_uri": responseUri]
        clientId.map { claims["client_id"] = $0 }
        return claims.merging(extra) { _, new in new }
    }

    private func x509Request(_ clientId: String, chain: [String] = [Cert.leaf, Cert.root],
                             key: P256.Signing.PrivateKey = Cert.leafKey) throws -> PresentationRequest {
        try RequestObjectParser.parse(Self.sign(["x5c": chain], claims(clientId), with: key))
    }

    private func verify(_ request: PresentationRequest, policy: PresentationRequestPolicy = .default) async throws -> VerifierIdentity {
        var request = request
        return try await ClientIdentifierVerifier().verify(&request, policy: policy)
    }

    private func refusal(_ request: PresentationRequest, policy: PresentationRequestPolicy = .default,
                         file: StaticString = #filePath, line: UInt = #line) async -> String {
        do {
            let identity = try await verify(request, policy: policy)
            XCTFail("expected a refusal, got \(identity)", file: file, line: line)
            return ""
        } catch let error as PresentationRequestError {
            XCTAssertEqual(error.eudiError.errorCode, "invalid_request", file: file, line: line)
            return error.message
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
            return ""
        }
    }

    private func resolve(_ data: String, policy: PresentationRequestPolicy = .default) async -> PresentationRequestOutcome {
        await PresentationRequestResolver(policy: policy).resolve(data)
    }

    private func byValue(_ params: [(String, String)]) -> String {
        var components = URLComponents(string: "openid4vp://")!
        components.queryItems = params.map { URLQueryItem(name: $0.0, value: $0.1) }
        return components.url!.absoluteString
    }

    private let dcql = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}"#

    // MARK: 2.1 and 2.2: redirect_uri

    func test2_1_anUnsignedRedirectUriRequestByValueGetsItsResponseUriFromTheClientId() async throws {
        let outcome = await resolve(byValue([("client_id", "redirect_uri:\(responseUri)"), ("response_type", "vp_token"),
                                             ("response_mode", "direct_post"), ("nonce", "n-1"), ("dcql_query", dcql)]))
        guard case .resolved(let resolved) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(resolved.request.responseUri, responseUri)
        XCTAssertEqual(resolved.verifier.identifier.prefix, .redirectUri)
        XCTAssertFalse(resolved.verifier.verified)
    }

    func test2_2_aSignedRedirectUriRequestIsAcceptedUnverifiedAndSaysTheSignatureWasIgnored() async throws {
        let request = try RequestObjectParser.parse(Self.sign([:], claims("redirect_uri:\(responseUri)"), with: P256.Signing.PrivateKey()))
        let identity = try await verify(request)
        XCTAssertFalse(identity.verified)
        XCTAssertEqual(identity.reason, "a redirect_uri request cannot be verified; its signature was ignored")
    }

    // MARK: 2.3 and 2.4: x509_san_dns

    func test2_3_x509SanDnsIsVerifiedAndNotAnchoredWithoutTrustAnchors() async throws {
        let identity = try await verify(try x509Request("x509_san_dns:\(host)"))
        XCTAssertTrue(identity.verified)
        XCTAssertFalse(identity.anchored)
        XCTAssertEqual(identity.certificateChain.count, 2)
        XCTAssertEqual(identity.redirectUriBound, true)
        XCTAssertEqual(identity.reason, "no trust anchors configured; the chain was checked for consistency only")
    }

    func test2_3b_x509SanDnsIsAnchoredWhenThePolicyTrustsTheRoot() async throws {
        let policy = PresentationRequestPolicy(trustAnchors: [Cert.certificate(Cert.root)], requireAnchoredClients: true)
        let identity = try await verify(try x509Request("x509_san_dns:\(host)"), policy: policy)
        XCTAssertTrue(identity.anchored)
        XCTAssertNil(identity.reason)
    }

    func test2_3c_aChainOfTheLeafAloneIsAnchoredByTheRoot() async throws {
        let policy = PresentationRequestPolicy(trustAnchors: [Cert.certificate(Cert.root)])
        let identity = try await verify(try x509Request("x509_san_dns:\(host)", chain: [Cert.leaf]), policy: policy)
        XCTAssertTrue(identity.anchored)
    }

    func test2_3d_anUnanchoredChainIsRefusedWhenThePolicyRequiresAnchoring() async throws {
        let message = await refusal(try x509Request("x509_san_dns:\(host)"), policy: PresentationRequestPolicy(requireAnchoredClients: true))
        XCTAssertTrue(message.contains("no trust anchors configured"), message)
    }

    func test2_3e_aChainEndingInAnotherRootIsRefusedWhenAnchorsAreSet() async throws {
        let policy = PresentationRequestPolicy(trustAnchors: [Cert.certificate(Cert.other)])
        let message = await refusal(try x509Request("x509_san_dns:\(host)"), policy: policy)
        XCTAssertTrue(message.hasSuffix("the x5c certificate chain does not end in a trusted anchor"), message)
    }

    func test2_3f_aResponseUriOnAnotherHostIsReportedNotRefused() async throws {
        var request = try x509Request("x509_san_dns:\(host)")
        request.responseUri = "https://elsewhere.example/response"
        let identity = try await verify(request)
        XCTAssertTrue(identity.verified)
        XCTAssertEqual(identity.redirectUriBound, false)
    }

    func test2_4_x509SanDnsRefusesASanMismatch() async throws {
        let message = await refusal(try x509Request("x509_san_dns:other.example.com"))
        XCTAssertTrue(message.hasSuffix("other.example.com is not a dNSName SAN of the leaf certificate"), message)
    }

    func test2_4b_x509SanDnsDoesNotAcceptAUriSan() async throws {
        let message = await refusal(try x509Request("x509_san_dns:https://verifier.example.com/callback"))
        XCTAssertTrue(message.contains("is not a dNSName SAN"), message)
    }

    func test2_4c_x509SanDnsRefusesASignatureByAnotherKey() async throws {
        let message = await refusal(try x509Request("x509_san_dns:\(host)", key: P256.Signing.PrivateKey()))
        XCTAssertTrue(message.hasSuffix("the request object is not signed with the leaf certificate's key"), message)
    }

    func test2_4d_x509SanDnsRefusesARequestWithoutX5c() async throws {
        let request = try RequestObjectParser.parse(Self.sign([:], claims("x509_san_dns:\(host)"), with: Cert.leafKey))
        let message = await refusal(request)
        XCTAssertTrue(message.hasSuffix("the request object carries no x5c certificate chain"), message)
    }

    func test2_4e_x509SanDnsRefusesAnExpiredLeaf() async throws {
        let message = await refusal(try x509Request("x509_san_dns:\(host)", chain: [Cert.expired, Cert.root]))
        XCTAssertTrue(message.hasSuffix("a certificate in the x5c chain is expired or not yet valid"), message)
    }

    func test2_4f_x509SanDnsRefusesAChainThatDoesNotLink() async throws {
        let message = await refusal(try x509Request("x509_san_dns:\(host)", chain: [Cert.leaf, Cert.other]))
        XCTAssertTrue(message.hasSuffix("the x5c certificate chain does not link"), message)
    }

    // MARK: 2.5: x509_hash

    func test2_5_x509HashIsVerifiedWhenTheHashNamesTheLeaf() async throws {
        let hash = RequestObjectCertificates.sha256Base64Url(Cert.certificate(Cert.leaf))
        let identity = try await verify(try x509Request("x509_hash:\(hash)"))
        XCTAssertTrue(identity.verified)
        XCTAssertFalse(identity.anchored)
    }

    func test2_5b_x509HashRefusesAHashOfAnotherCertificate() async throws {
        let hash = RequestObjectCertificates.sha256Base64Url(Cert.certificate(Cert.root))
        let message = await refusal(try x509Request("x509_hash:\(hash)"))
        XCTAssertTrue(message.hasSuffix("the client_id hash does not match the leaf certificate"), message)
    }

    // MARK: 2.6: decentralized_identifier

    private let verifierKey = P256.Signing.PrivateKey()

    private func didRequest(_ clientId: String, kid: String?, key: P256.Signing.PrivateKey? = nil,
                            header extra: [String: Any] = [:]) throws -> PresentationRequest {
        var header = extra
        kid.map { header["kid"] = $0 }
        return try RequestObjectParser.parse(Self.sign(header, claims(clientId), with: key ?? verifierKey))
    }

    func test2_6_aDidRequestSignedWithAKeyUnderTheClientDidIsVerified() async throws {
        let did = Self.didJwk(verifierKey.publicKey)
        let identity = try await verify(try didRequest("decentralized_identifier:\(did)", kid: "\(did)#0"))
        XCTAssertTrue(identity.verified)
        XCTAssertEqual(identity.identifier.identifier, did)
    }

    func test2_6b_theDraftBareDidSchemeFollowsTheSameRules() async throws {
        let did = Self.didJwk(verifierKey.publicKey)
        let identity = try await verify(try didRequest(did, kid: "\(did)#0"))
        XCTAssertEqual(identity.identifier.prefix, .did)
        XCTAssertTrue(identity.verified)
    }

    func test2_6c_aKidUnderAnotherDidIsRefused() async throws {
        let client = Self.didJwk(P256.Signing.PrivateKey().publicKey)
        let signer = Self.didJwk(verifierKey.publicKey)
        let message = await refusal(try didRequest("decentralized_identifier:\(client)", kid: "\(signer)#0"))
        XCTAssertTrue(message.hasSuffix("the kid does not belong to the client DID"), message)
    }

    func test2_6d_anEmbeddedJwkDoesNotStandInForTheDidKey() async throws {
        // Signed by a stranger who names the client's DID in kid and puts their own key in the header.
        let did = Self.didJwk(verifierKey.publicKey)
        let stranger = P256.Signing.PrivateKey()
        let request = try didRequest("decentralized_identifier:\(did)", kid: "\(did)#0", key: stranger,
                                     header: ["jwk": Self.jwk(stranger.publicKey)])
        let message = await refusal(request)
        XCTAssertTrue(message.hasSuffix("the request object signature does not verify"), message)
    }

    func test2_6e_aDidRequestWithoutKidIsRefused() async throws {
        let did = Self.didJwk(verifierKey.publicKey)
        let message = await refusal(try didRequest("decentralized_identifier:\(did)", kid: nil))
        XCTAssertTrue(message.hasSuffix("the request object names no kid for the verifier's key"), message)
    }

    // MARK: 2.7: verifier_attestation

    private let attesterKey = P256.Signing.PrivateKey()

    private func attestedRequest(sub: String = "verifier-1", clientId: String = "verifier_attestation:verifier-1",
                                 exp: Date = Date().addingTimeInterval(3600), iss: String? = nil,
                                 attestationKey: P256.Signing.PrivateKey? = nil, requestKey: P256.Signing.PrivateKey? = nil,
                                 redirectUris: [String]? = nil) throws -> PresentationRequest {
        var attestationClaims: [String: Any] = ["sub": sub, "iss": iss ?? Self.didJwk(attesterKey.publicKey),
                                                "exp": Int(exp.timeIntervalSince1970),
                                                "cnf": ["jwk": Self.jwk(verifierKey.publicKey)]]
        redirectUris.map { attestationClaims["redirect_uris"] = $0 }
        let attestation = Self.sign(["typ": "verifier-attestation+jwt"], attestationClaims, with: attestationKey ?? attesterKey)
        return try RequestObjectParser.parse(Self.sign(["jwt": attestation], claims(clientId), with: requestKey ?? verifierKey))
    }

    func test2_7_aSelfConsistentAttestationIsVerifiedButNotAnchored() async throws {
        let identity = try await verify(try attestedRequest())
        XCTAssertTrue(identity.verified)
        XCTAssertFalse(identity.anchored)
        XCTAssertTrue(identity.reason?.contains("self-consistent only") == true)
    }

    func test2_7b_anAttestationFromAConfiguredIssuerIsAnchored() async throws {
        let policy = PresentationRequestPolicy(verifierAttestationIssuerKeys: [Self.jwk(attesterKey.publicKey)],
                                               requireAnchoredClients: true)
        let identity = try await verify(try attestedRequest(iss: "https://attester.example"), policy: policy)
        XCTAssertTrue(identity.anchored)
    }

    func test2_7c_aSelfConsistentAttestationIsRefusedWhenAnchoringIsRequired() async throws {
        let message = await refusal(try attestedRequest(), policy: PresentationRequestPolicy(requireAnchoredClients: true))
        XCTAssertTrue(message.contains("self-consistent only"), message)
    }

    func test2_7d_anAttestationSubOtherThanTheClientIdIsRefused() async throws {
        let message = await refusal(try attestedRequest(sub: "someone-else"))
        XCTAssertTrue(message.hasSuffix("the verifier attestation sub does not match the client identifier"), message)
    }

    func test2_7e_anExpiredAttestationIsRefused() async throws {
        let message = await refusal(try attestedRequest(exp: Date().addingTimeInterval(-60)))
        XCTAssertTrue(message.hasSuffix("the verifier attestation has expired"), message)
    }

    func test2_7f_aRequestNotSignedWithTheAttestedKeyIsRefused() async throws {
        let message = await refusal(try attestedRequest(requestKey: P256.Signing.PrivateKey()))
        XCTAssertTrue(message.hasSuffix("the request object is not signed with the attested key"), message)
    }

    func test2_7g_anAttestationNotSignedByItsIssuerDidIsRefused() async throws {
        let message = await refusal(try attestedRequest(attestationKey: P256.Signing.PrivateKey()))
        XCTAssertTrue(message.contains("the verifier attestation signature does not verify against its issuer"), message)
    }

    func test2_7h_anAttestationFromAnUnknownNonDidIssuerIsRefused() async throws {
        let message = await refusal(try attestedRequest(iss: "https://attester.example"))
        XCTAssertTrue(message.hasSuffix("the verifier attestation is not signed by a trusted issuer"), message)
    }

    func test2_7i_aResponseUriOutsideTheAttestedRedirectUrisIsRefused() async throws {
        let message = await refusal(try attestedRequest(redirectUris: ["https://verifier.example.com/other"]))
        XCTAssertTrue(message.hasSuffix("the redirect_uri is not among the attestation's redirect_uris"), message)
        let identity = try await verify(try attestedRequest(redirectUris: [responseUri]))
        XCTAssertTrue(identity.verified)
    }

    // MARK: 2.8 to 2.13

    func test2_8_openidFederationIsRefusedAndNotAdvertised() async throws {
        let request = try RequestObjectParser.parse(Self.sign([:], claims("openid_federation:https://fed.example"), with: verifierKey))
        let message = await refusal(request)
        XCTAssertEqual(message, "The client identifier prefix 'openid_federation' is not supported")
        XCTAssertFalse(ClientIdentifierVerifier().supportedPrefixes(.default).contains("openid_federation"))
    }

    func test2_9_aClientIdWithoutPrefixIsAPreRegisteredClientAndStrictRefusesIt() async throws {
        let request = try RequestObjectParser.parse(Self.sign([:], claims("verifier-1"), with: verifierKey))
        let identity = try await verify(request)
        XCTAssertEqual(identity.identifier.prefix, .preRegistered)
        XCTAssertFalse(identity.verified)
        let message = await refusal(request, policy: .strict)
        XCTAssertTrue(message.hasSuffix("pre-registered clients are not accepted"), message)
    }

    func test2_9b_theDraftHttpsSchemeIsAPreRegisteredClient() async throws {
        let request = try RequestObjectParser.parse(Self.sign([:], claims("https://verifier.example.com"), with: verifierKey))
        let identity = try await verify(request)
        XCTAssertEqual(identity.identifier.prefix, .https)
        XCTAssertFalse(identity.verified)
    }

    func test2_10_aVersion1PrefixWinsOverTheDraftClientIdSchemeParameter() {
        XCTAssertEqual(ClientIdentifier.parse("x509_san_dns:\(host)", legacyScheme: "did").prefix, .x509SanDns)
        let draft = ClientIdentifier.parse(host, legacyScheme: "x509_san_dns")
        XCTAssertEqual(draft.prefix, .x509SanDns)
        XCTAssertEqual(draft.identifier, host)
    }

    func test2_11_webOriginIsAcceptedUnverifiedAndOriginIsRefused() async throws {
        var webOrigin = PresentationRequest(state: nil, clientId: "web-origin:https://rp.example", redirectUri: nil, responseUri: nil,
                                            responseType: "vp_token", responseMode: "dc_api", scope: nil, nonce: "n-1",
                                            requestUri: nil, presentationDefinition: nil, clientMetaData: nil,
                                            presentationDefinitionUri: nil, clientMetaDataUri: nil, clientIDScheme: nil,
                                            transactionData: [], request: nil, authSession: nil)
        let identity = try await verify(webOrigin)
        XCTAssertEqual(identity.identifier.prefix, .webOrigin)
        XCTAssertFalse(identity.verified)

        webOrigin.clientId = "origin:https://rp.example"
        let message = await refusal(webOrigin)
        XCTAssertTrue(message.hasSuffix("the origin prefix is reserved for the Digital Credentials API"), message)
    }

    func test2_12_x509SanUriIsVerifiedAgainstTheUriSan() async throws {
        let identity = try await verify(try x509Request("x509_san_uri:https://verifier.example.com/callback"))
        XCTAssertEqual(identity.identifier.prefix, .x509SanUri)
        XCTAssertTrue(identity.verified)
        let message = await refusal(try x509Request("x509_san_uri:https://other.example/callback"))
        XCTAssertTrue(message.contains("is not a URI SAN"), message)

        // Draft 20 shape: the bare URI in client_id, the scheme in client_id_scheme.
        var draft = try x509Request("https://verifier.example.com/callback")
        draft.clientIDScheme = "x509_san_uri"
        let draftIdentity = try await verify(draft)
        XCTAssertEqual(draftIdentity.identifier.prefix, .x509SanUri)
        XCTAssertTrue(draftIdentity.verified)
    }

    func test2_13_anAbsentClientIdIsRefusedUnderEnforcedAndReportedUnderAudit() async throws {
        let request = try RequestObjectParser.parse(Self.sign([:], claims(nil), with: verifierKey))
        let message = await refusal(request)
        XCTAssertTrue(message.hasSuffix("the request carries no client_id"), message)

        let identity = try await verify(request, policy: PresentationRequestPolicy(clientVerification: .audit))
        XCTAssertFalse(identity.verified)
        XCTAssertEqual(identity.reason, message)
    }

    // MARK: 2.14 and 2.15

    func test2_14_verifierInfoIsCarriedAsTheJsonReceived() throws {
        let request = try RequestObjectParser.parse(Self.sign([:], claims("redirect_uri:\(responseUri)", extra: [
            "verifier_info": [["format": "jwt", "data": "eyJ..."]]]), with: verifierKey))
        let info = try XCTUnwrap(request.verifierInfo)
        let parsed = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(info.utf8)) as? [[String: Any]])
        XCTAssertEqual(parsed.first?["format"] as? String, "jwt")
    }

    func test2_15_aByValueRequestNamingAnAuthenticatingPrefixIsRefused() async throws {
        let outcome = await resolve(byValue([("client_id", "x509_san_dns:\(host)"), ("response_type", "vp_token"),
                                             ("response_mode", "direct_post"), ("response_uri", responseUri),
                                             ("nonce", "n-1"), ("dcql_query", dcql)]))
        guard case .failed(let error) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(error.message, "The verifier could not be authenticated: the x509_san_dns prefix requires a signed request object and the request carries none")
        XCTAssertEqual(error.errorCode, "invalid_request")
    }

    // MARK: Policy and registry

    func testOffSkipsTheCheck() async throws {
        let identity = try await verify(try x509Request("x509_san_dns:other.example.com"),
                                        policy: PresentationRequestPolicy(clientVerification: .off))
        XCTAssertFalse(identity.verified)
        XCTAssertEqual(identity.reason, "client verification is off")
    }

    func testTheAdvertisedPrefixesAreTheVersion1PrefixesTheRegistryVerifies() {
        let expected = ["redirect_uri", "x509_san_dns", "x509_hash", "decentralized_identifier", "verifier_attestation"]
        XCTAssertEqual(ClientIdentifierVerifier().supportedPrefixes(.default), expected)
        let metadata = try? JSONSerialization.jsonObject(with: Data(RequestUriMethod.walletMetadata().utf8)) as? [String: Any]
        XCTAssertEqual(metadata?["client_id_prefixes_supported"] as? [String], expected)
    }
}
