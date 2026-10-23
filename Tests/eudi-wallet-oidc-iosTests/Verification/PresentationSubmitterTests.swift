//
//  PresentationSubmitterTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

/// Leg 5, response submission: the rows of the case matrix in `VERIFICATION_REVAMP_PLAN_IOS.md`,
/// numbered as there. Case names follow the Android SDK's `PresentationSubmitterTest`.
final class PresentationSubmitterTests: ResponseCharacterisationTestCase {

    private typealias F = VerificationFixtures

    private let verifierKey = VerifierKey()
    private var originalSession: URLSession!

    override func setUp() {
        super.setUp()
        StubURLProtocol.handler = nil
        StubURLProtocol.lastRequest = nil
        originalSession = DirectPostClient.session
        DirectPostClient.session = StubURLProtocol.session()
    }

    override func tearDown() {
        DirectPostClient.session = originalSession
        StubURLProtocol.handler = nil
        StubURLProtocol.lastRequest = nil
        super.tearDown()
    }

    private func submit(_ request: PresentationRequest, _ selected: [SelectedCredential]? = nil,
                        attestation: WalletAttestation? = nil) async -> PresentationOutcome {
        await PresentationSubmitter().submit(request, selected: selected ?? [SelectedCredential(entryId: "pid", credential: F.sdJwt(), keyId: "holder")],
                                             identity: WalletIdentity(did: F.did), holderKey: walletKeyHandler,
                                             attestation: attestation, authentication: nil)
    }

    private func answer(status: Int, headers: [String: String] = ["Content-Type": "application/json"], body: String = "") {
        StubURLProtocol.handler = { request in
            (HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: headers)!, Data(body.utf8))
        }
    }

    /// The form fields of the last POST.
    private var posted: [String: String] {
        guard let request = StubURLProtocol.lastRequest else { return [:] }
        var data = request.httpBody ?? Data()
        if data.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let read = stream.read(&buffer, maxLength: buffer.count)
                if read <= 0 { break }
                data.append(buffer, count: read)
            }
            stream.close()
        }
        var fields: [String: String] = [:]
        for pair in String(decoding: data, as: UTF8.self).split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            fields[parts[0].removingPercentEncoding ?? parts[0]] = parts.count > 1 ? parts[1].removingPercentEncoding : ""
        }
        return fields
    }

    private func accepted(_ outcome: PresentationOutcome) -> (redirectUri: String?, location: String?, code: String?)? {
        if case let .accepted(redirectUri, location, code) = outcome { return (redirectUri, location, code) }
        return nil
    }

    private func refusal(_ outcome: PresentationOutcome) -> EUDIError? {
        if case let .refused(error) = outcome { return error }
        return nil
    }

    // MARK: Reading the verifier's answer

    func test5_1A200WithRedirectUriIsAcceptedWithIt() async {
        answer(status: 200, body: #"{"redirect_uri":"https://verifier.example.com/done"}"#)
        let outcome = await submit(F.dcqlRequest(F.dcqlSdJwt("pid")))
        XCTAssertEqual(accepted(outcome)?.redirectUri, "https://verifier.example.com/done")
    }

    func test5_2A200WithoutRedirectUriOrWithANonJsonBodyIsAcceptedWithNothingFurther() async {
        answer(status: 200, body: "{}")
        let empty = accepted(await submit(F.dcqlRequest(F.dcqlSdJwt("pid"))))
        XCTAssertNotNil(empty)
        XCTAssertNil(empty?.redirectUri)
        XCTAssertNil(empty?.code)

        answer(status: 200, headers: ["Content-Type": "text/plain"], body: "ok")
        let result1 = await submit(F.dcqlRequest(F.dcqlSdJwt("pid")))
        XCTAssertNil(accepted(result1)?.redirectUri)
    }

    func test5_3A200WithACodeCarriesItAsTheAuthorizationCode() async {
        answer(status: 200, body: #"{"code":"c-123"}"#)
        let result2 = await submit(F.dcqlRequest(F.dcqlSdJwt("pid")))
        XCTAssertEqual(accepted(result2)?.code, "c-123")
    }

    func test5_4A204IsAcceptedWithNothingFurther() async {
        answer(status: 204)
        let outcome = accepted(await submit(F.dcqlRequest(F.dcqlSdJwt("pid"))))
        XCTAssertNotNil(outcome)
        XCTAssertNil(outcome?.redirectUri)
        XCTAssertNil(outcome?.location)
    }

    func test5_5A3xxCarriesItsLocationOrTheErrorInIt() async {
        answer(status: 302, headers: ["Location": "https://verifier.example.com/login;jsessionid=1"])
        let result3 = await submit(F.dcqlRequest(F.dcqlSdJwt("pid")))
        XCTAssertEqual(accepted(result3)?.location,
                       "https://verifier.example.com/login;jsessionid=1")

        answer(status: 303, headers: ["Location": "https://verifier.example.com/cb?error=access_denied&error_description=User+said+no"])
        let queryError = refusal(await submit(F.dcqlRequest(F.dcqlSdJwt("pid"))))
        XCTAssertEqual(queryError?.errorCode, "access_denied")
        XCTAssertEqual(queryError?.message, "User said no")
        XCTAssertEqual(queryError?.httpStatus, 303)

        answer(status: 302, headers: ["Location": "https://verifier.example.com/cb#error=invalid_request"])
        let result4 = await submit(F.dcqlRequest(F.dcqlSdJwt("pid")))
        XCTAssertEqual(refusal(result4)?.errorCode, "invalid_request")
    }

    func test5_6A4xxIsRefusedWithTheOAuthError() async {
        answer(status: 400, body: #"{"error":"invalid_request","error_description":"vp_token is malformed"}"#)
        let error = refusal(await submit(F.dcqlRequest(F.dcqlSdJwt("pid"))))
        XCTAssertEqual(error?.errorCode, "invalid_request")
        XCTAssertEqual(error?.httpStatus, 400)
        XCTAssertEqual(error?.message, "vp_token is malformed")
    }

    func test5_7AnotherStatusIsRefused() async {
        answer(status: 201, body: "created")
        let result5 = await submit(F.dcqlRequest(F.dcqlSdJwt("pid")))
        XCTAssertNotNil(refusal(result5))
    }

    func test5_8ATransportFailureIsRefused() async {
        StubURLProtocol.handler = { _ in throw URLError(.notConnectedToInternet) }
        let result6 = await submit(F.dcqlRequest(F.dcqlSdJwt("pid")))
        XCTAssertNotNil(refusal(result6))
    }

    // MARK: Before anything is sent

    func test5_9ARequestWithoutResponseUriIsRefusedBeforeAnythingIsSent() async {
        var request = F.dcqlRequest(F.dcqlSdJwt("pid"))
        request.responseUri = nil
        request.redirectUri = " "
        answer(status: 200, body: "{}")

        let error = refusal(await submit(request))
        XCTAssertEqual(error?.message, SubmissionError.noResponseUri.errorDescription)
        XCTAssertEqual(error?.errorCode, "invalid_request")
        XCTAssertNil(StubURLProtocol.lastRequest)
    }

    func test5_10DirectPostJwtTakesAlgFromTheKeyAndEncFromThe10MetadataName() async throws {
        var jwk = verifierKey.publicJwk
        jwk["alg"] = "ECDH-ES+A256KW"
        jwk["kid"] = nil
        let metadata: [String: Any] = ["jwks": ["keys": [jwk]], "encrypted_response_enc_values_supported": ["A256GCM", "A128GCM"],
                                       "authorization_encrypted_response_alg": "ECDH-ES"]
        answer(status: 200, body: "{}")
        _ = await submit(F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "direct_post.jwt", clientMetadata: metadata))

        XCTAssertEqual(Set(posted.keys), ["response"])
        let jwe = try verifierKey.decrypt(try XCTUnwrap(posted["response"]))
        XCTAssertEqual(jwe.header.keyManagementAlgorithm, .ECDH_ES_A256KW, "the key's own alg wins over the draft parameter")
        XCTAssertEqual(jwe.header.contentEncryptionAlgorithm, .A128GCM, "A128GCM is preferred over A256GCM")
        XCTAssertNil(jwe.header.kid, "a key without kid is still usable")
        XCTAssertEqual(jwe.header.apv, Data(F.nonce.utf8).b64url)
        XCTAssertNotNil(jwe.payload["vp_token"] as? [String: Any])
    }

    func test5_10ADirectPostJwtWithNoEncMetadataDefaultsToA128Gcm() async throws {
        answer(status: 200, body: "{}")
        _ = await submit(F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "direct_post.jwt",
                                       clientMetadata: F.encryptionMetadata(verifierKey, encValues: nil)))
        let jwe = try verifierKey.decrypt(try XCTUnwrap(posted["response"]))
        XCTAssertEqual(jwe.header.contentEncryptionAlgorithm, .A128GCM)
    }

    func test5_11AnUnsupportedAlgOrEncIsRefusedAndNothingIsSent() async {
        answer(status: 200, body: "{}")
        let enc = refusal(await submit(F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "direct_post.jwt",
                                                     clientMetadata: F.encryptionMetadata(verifierKey, encValues: ["A192GCM"]))))
        XCTAssertEqual(enc?.errorCode, "invalid_request")

        let alg = refusal(await submit(F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "direct_post.jwt",
                                                     clientMetadata: F.encryptionMetadata(verifierKey, alg: "ECDH-ES+A192KW"))))
        XCTAssertEqual(alg?.errorCode, "invalid_request")

        let noKey = refusal(await submit(F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "direct_post.jwt", clientMetadata: [:])))
        XCTAssertEqual(noKey?.message, SubmissionError.noEncryptionKey.errorDescription)
        XCTAssertNil(StubURLProtocol.lastRequest)
    }

    func test5_12TheDcApiModesHandTheParametersBackAndTheCallersRequestIsUntouched() async throws {
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "dc_api")
        guard case let .delivered(parameters) = await submit(request) else { return XCTFail("expected delivered") }

        XCTAssertEqual(Set(parameters.keys), ["vp_token", "state"])
        let presented = try XCTUnwrap((F.object(parameters["vp_token"]) as? [String: Any])?["pid"] as? [String])
        XCTAssertEqual(JWTParts.claims(F.keyBindingJwt(presented[0]))?["aud"] as? String, "origin:\(F.clientId)")
        XCTAssertEqual(request.clientId, F.clientId)
        XCTAssertNil(StubURLProtocol.lastRequest)

        guard case let .delivered(encrypted) = await submit(F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "dc_api.jwt",
                                                                          clientMetadata: F.encryptionMetadata(verifierKey))) else {
            return XCTFail("expected delivered")
        }
        _ = try verifierKey.decrypt(try XCTUnwrap(encrypted["response"]))
    }

    func test5_13IarPostWrapsTheResponseWithTheAuthSessionAsJson() async throws {
        answer(status: 200, body: #"{"code":"c-1"}"#)
        var request = F.pexRequest(F.sdJwtDescriptor("pid"), responseMode: "iar-post")
        request.authSession = "as-1"
        _ = await submit(request)

        XCTAssertEqual(posted["auth_session"], "as-1")
        let inner = try XCTUnwrap(F.object(posted["openid4vp_presentation"]) as? [String: Any])
        let submission = try XCTUnwrap(F.object(inner["presentation_submission"]) as? [String: Any], "plain JSON, not percent-encoded")
        XCTAssertEqual((submission["descriptor_map"] as? [[String: Any]])?.first?["id"] as? String, "pid")

        var encrypted = F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "iar-post.jwt", clientMetadata: F.encryptionMetadata(verifierKey))
        encrypted.authSession = "as-2"
        _ = await submit(encrypted)
        let wrapped = try XCTUnwrap(F.object(posted["openid4vp_presentation"]) as? [String: Any], "JSON, not a Swift description")
        _ = try verifierKey.decrypt(try XCTUnwrap(wrapped["response"] as? String))
    }

    func test5_15AnUnsupportedResponseModeIsRefused() async {
        let error = refusal(await submit(F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "fragment")))
        XCTAssertEqual(error?.errorCode, "invalid_request")
        XCTAssertEqual(error?.message, "The response mode 'fragment' is not supported")
    }

    func test5_16AProofThatCannotBeMadeIsRefusedAndNothingIsSent() async {
        answer(status: 200, body: "{}")
        let sdJwt = refusal(await submit(F.dcqlRequest(F.dcqlSdJwt("pid")),
                                         [SelectedCredential(entryId: "pid", credential: F.sdJwt(), keyId: "missing")]))
        XCTAssertEqual(sdJwt?.errorCode, "invalid_request")

        let mdoc = refusal(await submit(F.dcqlRequest(F.dcqlMdoc("mdl")),
                                        [SelectedCredential(entryId: "mdl", credential: F.mdoc(deviceKey: nil))]))
        XCTAssertNotNil(mdoc)
        XCTAssertNil(StubURLProtocol.lastRequest)
    }

    // MARK: What is sent

    func test5_17TheDcqlVpTokenIsKeyedByEntryId() async throws {
        answer(status: 200, body: "{}")
        _ = await submit(F.dcqlRequest(F.dcqlSdJwt("a"), F.dcqlSdJwt("b")),
                         [SelectedCredential(entryId: "b", credential: F.sdJwt(), keyId: "holder")])

        let vpToken = try XCTUnwrap(F.object(posted["vp_token"]) as? [String: Any])
        XCTAssertEqual(Set(vpToken.keys), ["b"])
        XCTAssertEqual(posted["state"], F.state)
    }

    func test5_18AnUnknownResponseTypeIsRefused() async {
        let error = refusal(await submit(F.pexRequest(F.sdJwtDescriptor("pid"), responseType: "code")))
        XCTAssertEqual(error?.errorCode, "unsupported_response_type")
    }

    func test5_19TheWalletUnitAttestationTravelsAsClientAttestationHeadersOnlyWhenPresent() async {
        answer(status: 200, body: "{}")
        _ = await submit(F.dcqlRequest(F.dcqlSdJwt("pid")), attestation: WalletAttestation(attestationJwt: "wua.jwt.sig~", proofOfPossession: "pop"))
        XCTAssertEqual(StubURLProtocol.lastRequest?.value(forHTTPHeaderField: "OAuth-Client-Attestation"), "wua.jwt.sig")
        XCTAssertEqual(StubURLProtocol.lastRequest?.value(forHTTPHeaderField: "OAuth-Client-Attestation-PoP"), "pop")

        _ = await submit(F.dcqlRequest(F.dcqlSdJwt("pid")), attestation: WalletAttestation(attestationJwt: "", proofOfPossession: ""))
        XCTAssertNil(StubURLProtocol.lastRequest?.value(forHTTPHeaderField: "OAuth-Client-Attestation"))
        XCTAssertNil(StubURLProtocol.lastRequest?.value(forHTTPHeaderField: "OAuth-Client-Attestation-PoP"))
    }

    func test5_20SeveralPresentationsArePostedAsAJsonArray() async throws {
        answer(status: 200, body: "{}")
        _ = await submit(F.pexRequest(F.sdJwtDescriptor("a"), F.sdJwtDescriptor("b")),
                         [SelectedCredential(entryId: "a", credential: F.sdJwt(vct: "urn:a"), keyId: "holder"),
                          SelectedCredential(entryId: "b", credential: F.sdJwt(vct: "urn:b"), keyId: "holder")])

        XCTAssertEqual((F.object(posted["vp_token"]) as? [String])?.count, 2)
        XCTAssertNotNil(F.object(posted["presentation_submission"]) as? [String: Any])
    }

    // MARK: The previous API

    @available(*, deprecated)
    private func legacy(_ request: PresentationRequest, _ credentials: [[String]]) async -> WrappedVerificationResponse? {
        await VerificationService(keyhandler: walletKeyHandler).processOrSendAuthorizationResponse(
            did: F.did, presentationRequest: request, credentialsList: credentials, wua: "", pop: "",
            keyIds: credentials.map { $0.map { _ in "holder" } }, amrInherenceFactor: nil, amrKnowledgeFactor: nil)
    }

    @available(*, deprecated)
    func testTheDeprecatedEntryPointKeepsItsPlaceholderAndErrorShapes() async {
        answer(status: 200, body: "{}")
        let result7 = await legacy(F.dcqlRequest(F.dcqlSdJwt("pid")), [[F.sdJwt()]])
        XCTAssertEqual(result7?.data, "https://www.example.com?code=1")

        answer(status: 200, body: #"{"code":"c-9"}"#)
        let result8 = await legacy(F.dcqlRequest(F.dcqlSdJwt("pid")), [[F.sdJwt()]])
        XCTAssertEqual(result8?.data, "https://www.example.com?code=c-9")

        answer(status: 200, body: #"{"redirect_uri":"https://verifier.example.com/done"}"#)
        let result9 = await legacy(F.dcqlRequest(F.dcqlSdJwt("pid")), [[F.sdJwt()]])
        XCTAssertEqual(result9?.redirectUri, "https://verifier.example.com/done")

        answer(status: 302, headers: ["Location": "https://verifier.example.com/login"])
        let result10 = await legacy(F.dcqlRequest(F.dcqlSdJwt("pid")), [[F.sdJwt()]])
        XCTAssertEqual(result10?.location, "https://verifier.example.com/login")

        StubURLProtocol.handler = { _ in throw URLError(.timedOut) }
        let failed = await legacy(F.dcqlRequest(F.dcqlSdJwt("pid")), [[F.sdJwt()]])
        XCTAssertNotNil(failed, "a transport failure is an error, no longer nil")
        XCTAssertNotNil(failed?.error)

        let mismatch = await legacy(F.dcqlRequest(F.dcqlSdJwt("a"), F.dcqlSdJwt("b")), [[F.sdJwt()]])
        XCTAssertEqual(mismatch?.error?.message, "The selected credentials do not match the query")

        var noUri = F.dcqlRequest(F.dcqlSdJwt("pid"))
        noUri.responseUri = nil
        let result11 = await legacy(noUri, [[F.sdJwt()]])
        XCTAssertEqual(result11?.error?.message, SubmissionError.noResponseUri.errorDescription)
    }
}
