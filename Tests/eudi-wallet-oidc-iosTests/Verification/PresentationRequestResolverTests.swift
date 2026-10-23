//
//  PresentationRequestResolverTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

/// One test per row of the leg 1 case matrix (VERIFICATION_REVAMP_PLAN_IOS.md), named after it.
/// Fetches go to `StubURLProtocol`; the request objects use the `redirect_uri` prefix, whose
/// handler checks no signature, so no certificate handling is involved. The client identifier
/// rows of leg 2 are in `ClientIdentifierVerifierTests`.
final class PresentationRequestResolverTests: XCTestCase {

    private let clientId = "redirect_uri:https://verifier.example/response"
    private let session = StubURLProtocol.session()
    private var served: [String: (status: Int, body: String)] = [:]

    override func setUp() {
        super.setUp()
        served = [:]
        StubURLProtocol.handler = { [unowned self] request in
            let url = request.url!.absoluteString
            guard let answer = self.served[url] else { throw URLError(.cannotConnectToHost) }
            let response = HTTPURLResponse(url: request.url!, statusCode: answer.status, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, Data(answer.body.utf8))
        }
    }

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    // MARK: Helpers

    private func resolve(_ data: String?, policy: PresentationRequestPolicy = .default) async -> PresentationRequestOutcome {
        await PresentationRequestResolver(policy: policy, session: session).resolve(data)
    }

    private func legacy(_ data: String?) async -> (PresentationRequest?, EUDIError?) {
        let service = VerificationService(keyhandler: CryptoKitHandler())
        service.requestObjectSession = session
        return await service.processAuthorisationRequest(data: data)
    }

    private func resolved(_ outcome: PresentationRequestOutcome, file: StaticString = #filePath, line: UInt = #line) throws -> ResolvedPresentationRequest {
        guard case .resolved(let resolved) = outcome else {
            XCTFail("expected resolved, got \(outcome)", file: file, line: line)
            throw XCTSkip()
        }
        return resolved
    }

    private func failed(_ outcome: PresentationRequestOutcome, file: StaticString = #filePath, line: UInt = #line) throws -> EUDIError {
        guard case .failed(let error) = outcome else {
            XCTFail("expected failed, got \(outcome)", file: file, line: line)
            throw XCTSkip()
        }
        return error
    }

    private func encode(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? value
    }

    private func uri(_ params: [(String, String)]) -> String {
        "openid4vp://?" + params.map { "\($0.0)=\(encode($0.1))" }.joined(separator: "&")
    }

    private func json(_ object: Any) -> String { VerificationFixtures.json(object) }

    private var dcql: [String: Any] {
        ["credentials": [["id": "pid", "format": "dc+sd-jwt", "meta": ["vct_values": ["urn:eudi:pid:1"]],
                          "claims": [["path": ["family_name"]]]]]]
    }

    private var presentationDefinition: [String: Any] {
        ["id": "pd-1", "input_descriptors": [["id": "pid", "format": ["vc+sd-jwt": ["alg": ["ES256"]]],
                                              "constraints": ["fields": [["path": ["$.family_name"]]]]]]]
    }

    private func claims(_ extra: [String: Any] = [:], clientId: String? = nil) -> [String: Any] {
        var claims: [String: Any] = ["client_id": clientId ?? self.clientId, "response_type": "vp_token",
                                     "response_mode": "direct_post", "nonce": "n-1", "state": "s-1",
                                     "dcql_query": dcql]
        extra.forEach { claims[$0.key] = $0.value }
        return claims
    }

    /// A request object: `alg: none` with an empty signature, or a signed shape whose signature
    /// nothing in leg 1 checks.
    private func requestObject(_ claims: [String: Any], signed: Bool = false) -> String {
        let header = Data(json(["alg": signed ? "ES256" : "none", "typ": "oauth-authz-req+jwt"]).utf8).b64url
        let payload = Data(json(claims).utf8).b64url
        return "\(header).\(payload).\(signed ? "c2lnbmF0dXJl" : "")"
    }

    private let requestUri = "https://verifier.example/request/1"

    // MARK: 1.1 and 1.19: nothing to resolve

    func test1_1_nilOrBlankFailsWithNoRequestAndTheAdapterKeepsNilNil() async throws {
        for data in [nil, "", "   "] as [String?] {
            let error = try failed(await resolve(data))
            XCTAssertEqual(error.message, "This QR code does not contain a presentation request")
            let (request, legacyError) = await legacy(data)
            XCTAssertNil(request)
            XCTAssertNil(legacyError)
        }
    }

    func test1_19_noKnownParameterFailsWithNoRequestAndTheAdapterKeepsNilNil() async throws {
        let data = "openid4vp://?foo=bar"
        let failure = try failed(await resolve(data))
        XCTAssertEqual(failure.message, "This QR code does not contain a presentation request")
        let (request, error) = await legacy(data)
        XCTAssertNil(request)
        XCTAssertNil(error)
    }

    // MARK: 1.2 to 1.6: by value

    func test1_2_dcqlQueryByValueResolvesAsVersion1() async throws {
        let data = uri([("client_id", clientId), ("response_type", "vp_token"), ("response_mode", "direct_post"),
                        ("nonce", "n-1"), ("state", "s-1"), ("dcql_query", json(dcql))])
        let resolved = try resolved(await resolve(data))
        XCTAssertEqual(resolved.specVersion, .v1_0)
        XCTAssertEqual(resolved.source, "by_value")
        XCTAssertEqual(resolved.request.dcqlQuery?.credentials.first?.id, "pid")

        // The adapter hands back what the by-value path always did: absent parameters as "".
        let (request, error) = await legacy(data)
        XCTAssertNil(error)
        XCTAssertEqual(request?.clientId, clientId)
        XCTAssertEqual(request?.nonce, "n-1")
        XCTAssertEqual(request?.state, "s-1")
        XCTAssertEqual(request?.responseUri, "https://verifier.example/response", "filled from the redirect_uri client id since leg 2")
        XCTAssertEqual(request?.presentationDefinition, "")
        XCTAssertEqual(request?.transactionData, [], "was [\"\"], which no step read")
    }

    func test1_3_presentationDefinitionByValueResolvesAsDraftAndStrictRefusesIt() async throws {
        let data = uri([("client_id", clientId), ("nonce", "n-1"), ("response_type", "vp_token"),
                        ("presentation_definition", json(presentationDefinition))])
        let resolved = try resolved(await resolve(data))
        XCTAssertEqual(resolved.specVersion, .draft)
        XCTAssertEqual(resolved.request.presentationDefinition, json(presentationDefinition))
        let (request, error) = await legacy(data)
        XCTAssertNil(error)
        XCTAssertEqual(request?.presentationDefinition, json(presentationDefinition))

        let refused = try failed(await resolve(data, policy: .strict))
        XCTAssertEqual(refused.message, "This presentation request uses a draft format that is not supported")
    }

    func test1_4_presentationDefinitionUriIsFetched() async throws {
        served["https://verifier.example/pd"] = (200, json(presentationDefinition))
        let data = uri([("client_id", clientId), ("response_type", "vp_token"), ("presentation_definition_uri", "https://verifier.example/pd")])
        let resolved = try resolved(await resolve(data))
        XCTAssertEqual(resolved.specVersion, .draft)
        XCTAssertEqual(resolved.request.presentationDefinition, json(presentationDefinition))
    }

    func test1_4_aFailedPresentationDefinitionFetchFailsTheRequest() async throws {
        served["https://verifier.example/pd"] = (404, "{}")
        let data = uri([("client_id", clientId), ("response_type", "vp_token"), ("presentation_definition_uri", "https://verifier.example/pd")])
        let error = try failed(await resolve(data))
        XCTAssertTrue(error.message?.hasPrefix("The presentation definition could not be fetched") ?? false, error.message ?? "")
        let (request, legacyError) = await legacy(data)
        XCTAssertNil(request, "today this resolved with no query at all")
        XCTAssertNotNil(legacyError)
    }

    func test1_22_aPresentationDefinitionRequestIsRefusedUnlessItsResponseTypeCanBeAnswered() async throws {
        func pex(_ extra: [(String, String)] = []) async -> PresentationRequestOutcome {
            await resolve(uri([("client_id", clientId), ("nonce", "n-1"), ("presentation_definition", json(presentationDefinition))] + extra))
        }

        for type in ["vp_token", "id_token", "vp_token id_token", "vp_token+id_token"] {
            let outcome = await pex([("response_type", type)])
            XCTAssertEqual(try resolved(outcome).specVersion, .draft, type)
        }
        let unknown = try failed(await pex([("response_type", "code")]))
        XCTAssertEqual(unknown.errorCode, "unsupported_response_type")
        XCTAssertEqual(unknown.message, "The response type 'code' is not supported")
        let missing = try failed(await pex())
        XCTAssertEqual(missing.errorCode, "unsupported_response_type")
        XCTAssertEqual(missing.message, "The request names no response type")

        // 1.0 always answers with vp_token, so a DCQL request is not checked.
        _ = try resolved(await resolve(uri([("client_id", clientId), ("nonce", "n-1"), ("response_type", "code"),
                                            ("dcql_query", json(dcql))])))
    }

    func test1_5_clientMetadataUriIsFetchedAndAFailureIsNotFatal() async throws {
        served["https://verifier.example/meta"] = (200, #"{"client_name":"Verifier"}"#)
        let fetched = try resolved(await resolve(uri([("client_id", clientId), ("dcql_query", json(dcql)),
                                                       ("client_metadata_uri", "https://verifier.example/meta")])))
        XCTAssertEqual(fetched.request.clientMetaData, #"{"client_name":"Verifier"}"#)

        let missing = try resolved(await resolve(uri([("client_id", clientId), ("dcql_query", json(dcql)),
                                                       ("client_metadata_uri", "https://verifier.example/gone")])))
        XCTAssertNil(missing.request.clientMetaData)
    }

    func test1_6_dcqlQueryBesidePresentationDefinitionWinsAndTheDefinitionIsDropped() async throws {
        let resolved = try resolved(await resolve(uri([("client_id", clientId), ("dcql_query", json(dcql)),
                                                       ("presentation_definition", json(presentationDefinition))])))
        XCTAssertEqual(resolved.specVersion, .v1_0)
        XCTAssertNil(resolved.request.presentationDefinition)
        XCTAssertNotNil(resolved.request.dcqlQuery)
    }

    // MARK: 1.7 to 1.11: behind a request_uri

    func test1_7_aRequestObjectBehindRequestUriResolvesThroughTheClientHandler() async throws {
        served[requestUri] = (200, requestObject(claims(), signed: true))
        let data = uri([("client_id", clientId), ("request_uri", requestUri)])
        let resolved = try resolved(await resolve(data))
        XCTAssertEqual(resolved.source, "request_uri")
        XCTAssertEqual(resolved.request.clientId, clientId)
        // The redirect_uri handler fills response_uri from the client id, as it always has.
        XCTAssertEqual(resolved.request.responseUri, "https://verifier.example/response")
        XCTAssertEqual(resolved.request.request?.filter { $0 == "." }.count, 2)

        let (request, error) = await legacy(data)
        XCTAssertNil(error)
        XCTAssertEqual(request?.nonce, "n-1")
        XCTAssertEqual(request?.responseUri, "https://verifier.example/response")
    }

    func test1_7b_aPresentationDefinitionUriInsideARequestObjectIsFetched() async throws {
        served["https://verifier.example/pd"] = (200, json(presentationDefinition))
        var inner = claims(["presentation_definition_uri": "https://verifier.example/pd"])
        inner["dcql_query"] = nil
        served[requestUri] = (200, requestObject(inner))
        let resolved = try resolved(await resolve(uri([("request_uri", requestUri)])))
        XCTAssertEqual(resolved.specVersion, .draft)
        XCTAssertEqual(resolved.request.presentationDefinition, json(presentationDefinition), "today the handler path returned before the fetch")
    }

    func test1_8_aPlainJsonAnswerIsToleratedAsNonStandard() async throws {
        served[requestUri] = (200, json(claims()))
        let resolved = try resolved(await resolve(uri([("request_uri", requestUri)])))
        XCTAssertEqual(resolved.request.nonce, "n-1")
        XCTAssertNil(resolved.request.request)
    }

    func test1_9_anUnsignedRequestObjectIsRefusedUnlessTheClientIsRedirectUri() async throws {
        served[requestUri] = (200, requestObject(claims(clientId: "x509_san_dns:verifier.example")))
        let error = try failed(await resolve(uri([("request_uri", requestUri)])))
        XCTAssertEqual(error.message, "Request validation failed")

        served[requestUri] = (200, requestObject(claims()))
        _ = try resolved(await resolve(uri([("request_uri", requestUri)])))
    }

    func test1_11_aRequestUriMethodOtherThanPostIsAGet() async throws {
        served[requestUri] = (200, requestObject(claims()))
        _ = try resolved(await resolve(uri([("request_uri", requestUri), ("request_uri_method", "put")])))
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "GET")
    }

    // MARK: 1.12 and 1.13: request object by value

    func test1_12_aRequestParameterResolvesThroughTheRequestObjectSource() async throws {
        let resolved = try resolved(await resolve(uri([("client_id", clientId), ("request", requestObject(claims()))])))
        XCTAssertEqual(resolved.source, "request")
        XCTAssertEqual(resolved.request.nonce, "n-1")
        XCTAssertEqual(resolved.request.responseUri, "https://verifier.example/response")
    }

    func test1_12_aRequestParameterThatIsNotAJwtIsMalformed() async throws {
        let failure = try failed(await resolve(uri([("request", "not-a-jwt")])))
        XCTAssertEqual(failure.message, "Invalid Request")
    }

    func test1_13_aBareJwtResolvesThroughTheRequestObjectSource() async throws {
        let resolved = try resolved(await resolve(requestObject(claims())))
        XCTAssertEqual(resolved.source, "request")
        XCTAssertEqual(resolved.request.state, "s-1")
    }

    // MARK: 1.14: interactive authorization request

    func test1_14_anInteractiveAuthorizationRequestKeepsItsDcqlQueryAndParameters() async throws {
        let openid4vpRequest = json(["client_id": "redirect_uri:https://issuer.example", "nonce": "n-iar",
                                     "response_uri": "https://issuer.example/iar", "response_mode": "iar-post",
                                     "dcql_query": dcql])
        let data = uri([("type", "openid4vp_presentation"), ("auth_session", "as-1"), ("openid4vp_request", openid4vpRequest)])
        let resolved = try resolved(await resolve(data))
        XCTAssertEqual(resolved.source, "openid4vp_request")
        XCTAssertEqual(resolved.request.nonce, "n-iar", "today a dcql_query sent this into the by-value branch, which lost it")
        XCTAssertEqual(resolved.request.responseUri, "https://issuer.example/iar")
        XCTAssertEqual(resolved.request.clientId, "https://issuer.example")
        XCTAssertEqual(resolved.request.authSession, "as-1")
        XCTAssertEqual(resolved.request.type, "openid4vp_presentation")

        let (request, error) = await legacy(data)
        XCTAssertNil(error)
        XCTAssertEqual(request?.nonce, "n-iar")
    }

    func test1_14_anInnerRequestObjectReplacesTheOuterParametersButNotTheIssuerClientId() async throws {
        let inner = requestObject(claims(["nonce": "n-inner"]))
        let openid4vpRequest = json(["client_id": "redirect_uri:https://issuer.example", "request": inner])
        let resolved = try resolved(await resolve(uri([("type", "openid4vp_presentation"), ("openid4vp_request", openid4vpRequest)])))
        XCTAssertEqual(resolved.request.nonce, "n-inner")
        XCTAssertEqual(resolved.request.clientId, "https://issuer.example")
        XCTAssertEqual(resolved.request.request, inner)
    }

    // MARK: 1.15 and 1.16: RFC 9101 and section 5.10.1

    func test1_15_requestAndRequestUriTogetherAreRefused() async throws {
        let error = try failed(await resolve(uri([("request", requestObject(claims())), ("request_uri", requestUri)])))
        XCTAssertEqual(error.errorCode, "invalid_request")
    }

    func test1_16_aUriClientIdThatDiffersFromTheRequestObjectIsRefused() async throws {
        served[requestUri] = (200, requestObject(claims()))
        let byReference = try failed(await resolve(uri([("client_id", "redirect_uri:https://other.example"), ("request_uri", requestUri)])))
        XCTAssertEqual(byReference.errorCode, "invalid_request")
        XCTAssertEqual(byReference.message, "The client_id in the request does not match the request object")

        let byValue = try failed(await resolve(uri([("client_id", "redirect_uri:https://other.example"), ("request", requestObject(claims()))])))
        XCTAssertEqual(byValue.errorCode, "invalid_request")
    }

    // MARK: 1.17 and 1.18: failures

    func test1_17_aMalformedOrInvalidDcqlQueryIsRefusedWithItsCode() async throws {
        let malformed = try failed(await resolve(uri([("client_id", clientId), ("dcql_query", "{not json")])))
        XCTAssertEqual(malformed.code, ErrorCodes.invalidDcqlQuery)
        let invalid = try failed(await resolve(uri([("client_id", clientId), ("dcql_query", #"{"credentials":[]}"#)])))
        XCTAssertEqual(invalid.code, ErrorCodes.invalidDcqlQuery)
    }

    func test1_18_anHttpErrorOrTransportFailureFromTheRequestUriFails() async throws {
        served[requestUri] = (400, #"{"error":"invalid_request","error_description":"refused"}"#)
        let http = try failed(await resolve(uri([("request_uri", requestUri)])))
        XCTAssertTrue(http.message?.contains("refused") ?? false, http.message ?? "")

        let transport = try failed(await resolve(uri([("request_uri", "https://verifier.example/unreachable")])))
        XCTAssertNotNil(transport.message)
    }

    func test1_18b_anEmptyOrUnreadableRequestUriAnswerFails() async throws {
        served[requestUri] = (200, "")
        let empty = try failed(await resolve(uri([("request_uri", requestUri)])))
        XCTAssertEqual(empty.message, "Response is null or empty.")
        served[requestUri] = (200, "garbage")
        let garbage = try failed(await resolve(uri([("request_uri", requestUri)])))
        XCTAssertEqual(garbage.message, "Invalid Request")
        let (request, error) = await legacy(uri([("request_uri", requestUri)]))
        XCTAssertNil(request)
        XCTAssertNotNil(error, "today this was (nil, nil)")
    }

    func test1_18c_aRequestUriThatIsNotAUrlFailsInsteadOfCrashing() async throws {
        let error = try failed(await resolve(uri([("request_uri", "https://[invalid")])))
        XCTAssertEqual(error.message, "Invalid Request: request_uri is not a valid URL")
    }

    func test1_21_dcqlQueryBesideRequestUriKeepsTheByValueRequest() async throws {
        let resolved = try resolved(await resolve(uri([("client_id", clientId), ("dcql_query", json(dcql)), ("request_uri", requestUri)])))
        XCTAssertEqual(resolved.source, "by_value")
    }

    // MARK: Registry and adapter

    func testTheRegistryTriesVersion1MechanismsFirstAndTheExtensionLast() {
        XCTAssertEqual(PresentationRequestResolver.defaultSources(session: session).map(\.name),
                       ["by_value", "request_uri", "request", "openid4vp_request"])
    }

    func testAnUnknownPrefixResolvesAsAPreRegisteredClientAndTheAdapterNowReturnsIt() async throws {
        // Until leg 2 this failed and the adapter answered (nil, nil).
        let data = uri([("request", requestObject(claims(clientId: "unknown:verifier")))])
        let resolved = try resolved(await resolve(data))
        XCTAssertEqual(resolved.verifier.identifier.prefix, .preRegistered)
        XCTAssertFalse(resolved.verifier.verified)
        let (request, error) = await legacy(data)
        XCTAssertEqual(request?.clientId, "unknown:verifier")
        XCTAssertNil(error)
    }
}
