//
//  CredentialRequestTests.swift
//

import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// The credential request body, the proof it carries, and the answers it reads.
///
/// None of these could have been written before: the request went out through `NetworkLogger`'s
/// default `URLSession.shared`, so it could not be stubbed, and the proof was built inside a
/// 240-line function with no seam.
///
/// Mirrors `CredentialSubjectTest`, `CredentialRequestParametersTest` and
/// `CredentialRequestResolverTest` in the Android SDK.
final class CredentialRequestTests: XCTestCase {

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    // MARK: - Fixtures

    /// These models decode by **Swift property name** -- the snake_case wire mapping lives in the
    /// separate `...Response` types. `declaresAuthorizationServers` is a non-optional `Bool`, and a
    /// synthesised `Decodable` ignores property defaults, so it has to be present.
    private func issuerConfig(
        nonceEndpoint: String? = "https://issuer.example.com/nonce",
        configurationId: String = "PID",
        format: String = "dc+sd-jwt",
        hasProofTypes: Bool = true,
        credentialMetadata: Bool = false,
        bindingMethods: [String] = ["jwk"],
        vct: String? = "PidVct",
        docType: String? = nil
    ) -> IssuerWellKnownConfiguration {
        let json = """
        {
          "credentialIssuer": "https://issuer.example.com",
          "declaresAuthorizationServers": true,
          "credentialEndpoint": "https://issuer.example.com/credential",
          \(nonceEndpoint.map { "\"nonceEndPoint\": \"\($0)\"," } ?? "")
          "credentialsSupported": {
            "version": "v2",
            "dataSharing": {
              "\(configurationId)": {
                "format": "\(format)",
                "cryptographicBindingMethodsSupported": \(json(bindingMethods)),
                "hasProofTypesSupported": \(hasProofTypes),
                \(credentialMetadata ? "\"credentialMetadata\": {}," : "")
                \(docType.map { "\"docType\": \"\($0)\"," } ?? "")
                \(vct.map { "\"vct\": \"\($0)\"," } ?? "")
                "types": ["\(configurationId)"]
              }
            }
          }
        }
        """
        return try! JSONDecoder().decode(IssuerWellKnownConfiguration.self, from: Data(json.utf8))
    }

    private func json(_ values: [String]) -> String {
        "[" + values.map { "\"\($0)\"" }.joined(separator: ",") + "]"
    }

    private func offer(configurationIds: [String] = ["PID"]) -> CredentialOffer {
        let entries = configurationIds
            .map { "{\"types\": [\"\($0)\"]}" }
            .joined(separator: ",")
        let text = """
        {
          "credentialIssuer": "https://issuer.example.com",
          "version": "v2",
          "credentials": [\(entries)]
        }
        """
        return try! JSONDecoder().decode(CredentialOffer.self, from: Data(text.utf8))
    }

    private func session(
        nonceEndpoint: String? = "https://issuer.example.com/nonce",
        configurationId: String = "PID",
        format: String = "dc+sd-jwt",
        hasProofTypes: Bool = true,
        credentialMetadata: Bool = false,
        bindingMethods: [String] = ["jwk"],
        vct: String? = "PidVct",
        docType: String? = nil,
        offerIds: [String] = ["PID"]
    ) -> IssuanceSession {
        IssuanceSession(
            credentialOffer: offer(configurationIds: offerIds),
            issuerConfig: issuerConfig(
                nonceEndpoint: nonceEndpoint,
                configurationId: configurationId,
                format: format,
                hasProofTypes: hasProofTypes,
                credentialMetadata: credentialMetadata,
                bindingMethods: bindingMethods,
                vct: vct,
                docType: docType
            ),
            authConfig: nil
        )
    }

    private func token(
        authorizationDetails: [AuthorizationDetails]? = nil,
        cNonce: String? = "c-nonce-1",
        tokenType: String? = "Bearer"
    ) -> TokenResponse {
        var token = TokenResponse()
        token.accessToken = "access-1"
        token.tokenType = tokenType
        token.cNonce = cNonce
        token.authorizationDetails = authorizationDetails
        return token
    }

    private func detail(configId: String? = nil, identifiers: [String]? = nil) -> AuthorizationDetails {
        let text = """
        {
          "type": "openid_credential"
          \(configId.map { ", \"credential_configuration_id\": \"\($0)\"" } ?? "")
          \(identifiers.map { ", \"credential_identifiers\": \(json($0))" } ?? "")
        }
        """
        return try! JSONDecoder().decode(AuthorizationDetails.self, from: Data(text.utf8))
    }

    /// Runs a real request against the stub and returns the body the issuer received.
    @discardableResult
    private func capture(
        session: IssuanceSession,
        subject: CredentialSubject,
        token: TokenResponse? = nil,
        policy: CredentialRequestPolicy = .standard,
        attestation: WalletAttestation? = nil,
        keyHandler: StubKeyHandler = StubKeyHandler(),
        status: Int = 200,
        contentType: String? = "application/json",
        responseBody: String = #"{"credentials":[{"credential":"vc-1"}]}"#
    ) async -> (body: [String: Any], headers: [String: String], outcome: CredentialOutcome) {
        var seen: [String: Any] = [:]
        var seenHeaders: [String: String] = [:]
        StubURLProtocol.handler = { request in
            // A stubbed URLProtocol does not see `httpBody`; the body arrives as a stream.
            if request.url?.path.contains("credential") == true {
                seen = Self.body(of: request)
                seenHeaders = request.allHTTPHeaderFields ?? [:]
            }
            let headers = contentType.map { ["Content-Type": $0] } ?? [:]
            let response = HTTPURLResponse(
                url: request.url!, statusCode: status, httpVersion: nil, headerFields: headers
            )!
            return (response, Data(responseBody.utf8))
        }

        let outcome = await CredentialRequestResolver(policy: policy, keyHandler: keyHandler).resolve(
            session: session,
            wallet: WalletIdentity(did: "did:key:zabc"),
            token: token ?? self.token(),
            subject: subject,
            issuer: "did:key:zabc",
            attestation: attestation,
            nonce: "c-nonce-1",
            urlSession: StubURLProtocol.session()
        )
        return (seen, seenHeaders, outcome)
    }

    private static func body(of request: URLRequest) -> [String: Any] {
        guard let stream = request.httpBodyStream else {
            guard let data = request.httpBody else { return [:] }
            return ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any]) ?? [:]
        }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let size = 4096
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
        defer { buffer.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: size)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any]) ?? [:]
    }

    // MARK: - Section 8.2: the two identifiers are mutually exclusive

    func testByIdentifierSendsCredentialIdentifierAlone() async {
        let (body, _, _) = await capture(
            session: session(),
            subject: .byIdentifier(credentialIdentifier: "cred-abc", offerCredential: nil)
        )
        XCTAssertEqual(body["credential_identifier"] as? String, "cred-abc")
        XCTAssertNil(body["credential_configuration_id"])
        // 1.0 has no `format` member in the credential request.
        XCTAssertNil(body["format"])
    }

    func testByConfigurationSendsConfigurationIdAlone() async {
        let (body, _, _) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil)
        )
        XCTAssertEqual(body["credential_configuration_id"] as? String, "PID")
        XCTAssertNil(body["credential_identifier"])
        XCTAssertNil(body["format"])
    }

    func testLegacyMsoMdocSendsDoctypeAndFormat() async {
        let (body, _, _) = await capture(
            session: session(nonceEndpoint: nil, format: "mso_mdoc", hasProofTypes: false),
            subject: .legacyFormat(format: "mso_mdoc", docType: "eu.europa.ec.eudi.pid.1")
        )
        XCTAssertEqual(body["format"] as? String, "mso_mdoc")
        XCTAssertEqual(body["doctype"] as? String, "eu.europa.ec.eudi.pid.1")
        XCTAssertNil(body["credential_identifier"])
        XCTAssertNil(body["credential_configuration_id"])
    }

    // MARK: - Section 8.2: plural proofs

    func testProofsPluralWhenProofTypesSupportedIsDeclared() async {
        let (body, _, _) = await capture(
            session: session(hasProofTypes: true),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil)
        )
        let proofs = body["proofs"] as? [String: Any]
        XCTAssertEqual((proofs?["jwt"] as? [String])?.count, 1)
        XCTAssertNil(body["proof"])
    }

    func testProofSingularWhenProofTypesSupportedIsAbsent() async {
        let (body, _, _) = await capture(
            session: session(hasProofTypes: false),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil)
        )
        XCTAssertNil(body["proofs"])
        XCTAssertEqual((body["proof"] as? [String: Any])?["proof_type"] as? String, "jwt")
    }

    /// `credential_metadata` was the old trigger on both platforms. Section 8.2 keys the rule on
    /// `proof_types_supported`, and this is the test that the old marker stopped mattering.
    func testCredentialMetadataAloneDoesNotMakeProofsPlural() async {
        let (body, _, _) = await capture(
            session: session(hasProofTypes: false, credentialMetadata: true),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil)
        )
        XCTAssertNil(body["proofs"])
        XCTAssertNotNil(body["proof"])
    }

    func testPolicyCanForceTheSingularProof() async {
        let (body, _, _) = await capture(
            session: session(hasProofTypes: true),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            policy: .legacy
        )
        XCTAssertNil(body["proofs"])
        XCTAssertNotNil(body["proof"])
    }

    // MARK: - Section 8.2: which subject the token response requires

    func testIdentifierWinsWhenTheTokenResponseReturnedOne() {
        let subject = CredentialSubject.of(
            session: session(),
            token: token(authorizationDetails: [detail(configId: "PID", identifiers: ["cred-1"])]),
            credential: offer().credentials?.first
        )
        guard case let .byIdentifier(identifier, _) = subject else {
            return XCTFail("expected byIdentifier, got \(subject)")
        }
        XCTAssertEqual(identifier, "cred-1")
    }

    func testConfigurationIdWhenNoIdentifiersCameBack() {
        let subject = CredentialSubject.of(
            session: session(),
            token: token(authorizationDetails: [detail(configId: "PID")]),
            credential: offer().credentials?.first
        )
        guard case let .byConfiguration(id, _) = subject else {
            return XCTFail("expected byConfiguration, got \(subject)")
        }
        XCTAssertEqual(id, "PID")
    }

    /// The bug this replaced: with several authorization details and none naming this credential,
    /// the first one's `credential_identifier` was borrowed -- so the issuer was asked for a
    /// credential the wallet was not requesting, and only for the entries after the first.
    func testDoesNotBorrowAnotherCredentialsIdentifier() {
        let subject = CredentialSubject.of(
            session: session(offerIds: ["PID", "MDL"]),
            token: token(authorizationDetails: [
                detail(configId: "OTHER_A", identifiers: ["cred-a"]),
                detail(configId: "OTHER_B", identifiers: ["cred-b"]),
            ]),
            credential: offer(configurationIds: ["PID"]).credentials?.first
        )
        guard case let .byConfiguration(id, _) = subject else {
            return XCTFail("expected byConfiguration, got \(subject)")
        }
        XCTAssertEqual(id, "PID")
    }

    /// One detail is unambiguous -- it is the single-credential case, and it must still be used.
    func testASingleDetailIsUsedEvenWhenItDoesNotNameTheCredential() {
        let subject = CredentialSubject.of(
            session: session(),
            token: token(authorizationDetails: [detail(configId: "OTHER", identifiers: ["cred-only"])]),
            credential: offer().credentials?.first
        )
        guard case let .byIdentifier(identifier, _) = subject else {
            return XCTFail("expected byIdentifier, got \(subject)")
        }
        XCTAssertEqual(identifier, "cred-only")
    }

    /// No nonce endpoint means a pre-1.0 issuer, which has neither identifier.
    func testFallsBackToTheDraftShapeWithoutANonceEndpoint() {
        let subject = CredentialSubject.of(
            session: session(nonceEndpoint: nil, format: "mso_mdoc", vct: nil, docType: "doc.type.1"),
            token: token(),
            credential: offer().credentials?.first
        )
        guard case let .legacyFormat(format, _, _, _, _, _) = subject else {
            return XCTFail("expected legacyFormat, got \(subject)")
        }
        XCTAssertEqual(format, "mso_mdoc")
    }

    // MARK: - The proof

    func testProofCarriesTheRequiredClaims() async {
        let keyHandler = StubKeyHandler()
        let (body, _, _) = await capture(
            session: session(hasProofTypes: false),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            keyHandler: keyHandler
        )
        let jwt = (body["proof"] as? [String: Any])?["jwt"] as? String
        let header = JWTParts.header(jwt ?? "")
        let claims = JWTParts.claims(jwt ?? "")

        XCTAssertEqual(header?["typ"] as? String, "openid4vci-proof+jwt")
        XCTAssertEqual(header?["alg"] as? String, "ES256")
        XCTAssertEqual(claims?["iss"] as? String, "did:key:zabc")
        XCTAssertEqual(claims?["aud"] as? String, "https://issuer.example.com")
        XCTAssertEqual(claims?["nonce"] as? String, "c-nonce-1")

        // The Android bug this pairs with: `Date(Date().time + 86400)` expired the proof 86.4
        // seconds out, because Date.time is milliseconds. iOS was already correct; this is the
        // test that keeps it so.
        let issuedAt = claims?["iat"] as? Int ?? 0
        XCTAssertEqual((claims?["exp"] as? Int ?? 0) - issuedAt, 86_400)
    }

    /// Section 8.2 makes the nonce REQUIRED when the issuer publishes a Nonce Endpoint. It used to
    /// be omitted silently, producing `invalid_proof` a round trip later with nothing saying why.
    func testMissingNonceAgainstANonceEndpointIsANamedFailure() async {
        StubURLProtocol.respond(status: 200, body: "{}")
        let outcome = await CredentialRequestResolver(keyHandler: StubKeyHandler()).resolve(
            session: session(nonceEndpoint: "https://issuer.example.com/nonce"),
            wallet: WalletIdentity(did: "did:key:zabc"),
            token: token(cNonce: nil),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            issuer: "did:key:zabc",
            urlSession: StubURLProtocol.session()
        )
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(error.message?.contains("c_nonce") == true, error.message ?? "")
    }

    /// RFC 7638 over `crv`/`kty`/`x`/`y` only. iOS hashed the whole JWK with `.sortedKeys`, so any
    /// incidental member changed it; Android used the key's own `kid`. Neither was the standard,
    /// and the two platforms disagreed for the same key.
    func testJwkBindingMethodUsesAnRFC7638Thumbprint() async {
        let keyHandler = StubKeyHandler()
        let (body, _, _) = await capture(
            session: session(hasProofTypes: false, bindingMethods: ["jwk"]),
            subject: .byConfiguration(
                credentialConfigurationId: "PID",
                offerCredential: offer().credentials?.first
            ),
            keyHandler: keyHandler
        )
        let jwt = (body["proof"] as? [String: Any])?["jwt"] as? String
        let header = JWTParts.header(jwt ?? "")

        // The offer entry carries no trustFramework, so the `jwk` method takes the else-branch and
        // the key travels in the header rather than as a kid.
        XCTAssertNotNil(header?["jwk"])
        XCTAssertEqual(
            JWKThumbprint.rfc7638(of: keyHandler.publicJWK),
            JWKThumbprint.rfc7638(of: header?["jwk"] as? [String: Any] ?? [:])
        )
    }

    func testDidBindingMethodPutsAKidInTheHeader() async {
        let (body, _, _) = await capture(
            session: session(hasProofTypes: false, bindingMethods: ["did:key"]),
            subject: .byConfiguration(
                credentialConfigurationId: "PID",
                offerCredential: offer().credentials?.first
            )
        )
        let header = JWTParts.header((body["proof"] as? [String: Any])?["jwt"] as? String ?? "")
        XCTAssertEqual(header?["kid"] as? String, "did:key:zabc#zabc")
        XCTAssertNil(header?["jwk"])
    }

    // MARK: - Reading the answer

    func testEveryCredentialInAPluralResponseIsReturned() async {
        let (_, _, outcome) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            responseBody: #"{"credentials":[{"credential":"vc-1"},{"credential":"vc-2"}],"notification_id":"n-1","c_nonce":"next"}"#
        )
        guard case let .issued(credentials, notificationId, cNonce) = outcome else {
            return XCTFail("expected issued, got \(outcome)")
        }
        XCTAssertEqual(credentials, ["vc-1", "vc-2"])
        XCTAssertEqual(notificationId, "n-1")
        XCTAssertEqual(cNonce, "next")
    }

    /// The deferred leg reuses the handle it is polling with when an issuer defers without naming
    /// one. The credential leg must not: this is the *first* request, so there is no prior handle,
    /// and inventing one would start polling something that was never allocated.
    func testA200CarryingOnlyAnIntervalIsAFailureOnTheCredentialLeg() async {
        let (_, _, outcome) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            responseBody: #"{"interval":7}"#
        )
        guard case .failed = outcome else { return XCTFail("expected failure, got \(outcome)") }
    }

    func testASingularDraftCredentialStillArrives() async {
        let (_, _, outcome) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            responseBody: #"{"credential":"vc-only"}"#
        )
        XCTAssertEqual(outcome.firstCredential, "vc-only")
    }

    func testTransactionIdIsRecognisedAsDeferred() async {
        let (_, _, outcome) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            responseBody: #"{"transaction_id":"txn-1","interval":5}"#
        )
        guard case let .deferred(transactionId, interval) = outcome else {
            return XCTFail("expected deferred, got \(outcome)")
        }
        XCTAssertEqual(transactionId, "txn-1")
        XCTAssertEqual(interval, 5)
    }

    func testTheDraftAcceptanceTokenIsAlsoDeferred() async {
        let (_, _, outcome) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            responseBody: #"{"acceptance_token":"acc-1"}"#
        )
        guard case let .deferred(transactionId, _) = outcome else {
            return XCTFail("expected deferred, got \(outcome)")
        }
        XCTAssertEqual(transactionId, "acc-1")
    }

    /// `SafeApiCall` on Android and the bare status check here both lost this. A caller cannot tell
    /// `invalid_proof` from an expired token without it.
    func testARejectionCarriesTheErrorCodeAndTheStatus() async {
        let (_, _, outcome) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            status: 400,
            responseBody: #"{"error":"invalid_credential_request","error_description":"bad shape"}"#
        )
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertEqual(error.errorCode, "invalid_credential_request")
        XCTAssertEqual(error.httpStatus, 400)
        XCTAssertEqual(error.message, "bad shape")
    }

    /// A 4xx with nothing in it must not decode as a success.
    func testAnEmptyErrorBodyIsStillAFailure() async {
        let (_, _, outcome) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            status: 500,
            responseBody: ""
        )
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertEqual(error.httpStatus, 500)
    }

    func testA200WithNeitherCredentialNorTransactionIdIsAFailure() async {
        let (_, _, outcome) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            responseBody: "{}"
        )
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(error.message?.contains("neither") == true, error.message ?? "")
    }

    /// Section 8.3.1 lets the issuer hand back a fresh nonce with the rejection; the wallet should
    /// sign again with it. Exactly once -- a second failure gives up rather than looping.
    func testAStaleNonceIsRetriedOnceWithTheFreshOne() async {
        var attempts = 0
        var noncesSent: [String] = []
        StubURLProtocol.handler = { request in
            if request.url?.path.contains("credential") == true {
                attempts += 1
                let body = Self.body(of: request)
                let jwt = (body["proofs"] as? [String: Any]).flatMap { ($0["jwt"] as? [String])?.first }
                    ?? ((body["proof"] as? [String: Any])?["jwt"] as? String)
                if let nonce = JWTParts.claims(jwt ?? "")?["nonce"] as? String {
                    noncesSent.append(nonce)
                }
            }
            let response = HTTPURLResponse(
                url: request.url!, statusCode: 400, httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, Data(#"{"error":"invalid_proof","c_nonce":"fresh-nonce"}"#.utf8))
        }

        let outcome = await CredentialRequestResolver(keyHandler: StubKeyHandler()).resolve(
            session: session(),
            wallet: WalletIdentity(did: "did:key:zabc"),
            token: token(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            issuer: "did:key:zabc",
            nonce: "c-nonce-1",
            urlSession: StubURLProtocol.session()
        )

        XCTAssertEqual(attempts, 2, "one retry, not a loop")
        XCTAssertEqual(noncesSent, ["c-nonce-1", "fresh-nonce"])
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertEqual(error.errorCode, "invalid_proof")
    }

    func testAStaleNonceIsNotRetriedWhenThePolicySaysNot() async {
        var attempts = 0
        StubURLProtocol.handler = { request in
            if request.url?.path.contains("credential") == true { attempts += 1 }
            let response = HTTPURLResponse(
                url: request.url!, statusCode: 400, httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, Data(#"{"error":"invalid_proof","c_nonce":"fresh-nonce"}"#.utf8))
        }

        _ = await CredentialRequestResolver(policy: .legacy, keyHandler: StubKeyHandler()).resolve(
            session: session(),
            wallet: WalletIdentity(did: "did:key:zabc"),
            token: token(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            issuer: "did:key:zabc",
            nonce: "c-nonce-1",
            urlSession: StubURLProtocol.session()
        )
        XCTAssertEqual(attempts, 1)
    }

    /// RFC 9449 section 8. The token endpoint has answered this challenge since step 4; the
    /// credential endpoint never has.
    func testADPoPNonceChallengeIsRetriedOnce() async {
        var attempts = 0
        var authorizations: [String] = []
        StubURLProtocol.handler = { request in
            guard request.url?.path.contains("credential") == true else {
                let ok = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (ok, Data("{}".utf8))
            }
            attempts += 1
            authorizations.append(request.value(forHTTPHeaderField: "Authorization") ?? "")
            if attempts == 1 {
                let challenge = HTTPURLResponse(
                    url: request.url!, statusCode: 400, httpVersion: nil,
                    headerFields: ["Content-Type": "application/json", "DPoP-Nonce": "dpop-1"]
                )!
                return (challenge, Data(#"{"error":"use_dpop_nonce"}"#.utf8))
            }
            let ok = HTTPURLResponse(
                url: request.url!, statusCode: 200, httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (ok, Data(#"{"credentials":[{"credential":"vc-1"}]}"#.utf8))
        }

        let outcome = await CredentialRequestResolver(keyHandler: StubKeyHandler()).resolve(
            session: session(),
            wallet: WalletIdentity(did: "did:key:zabc"),
            token: token(tokenType: "DPoP"),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            issuer: "did:key:zabc",
            attestation: WalletAttestation(
                attestationJwt: nil, proofOfPossession: nil, dpopKey: P256.Signing.PrivateKey()
            ),
            nonce: "c-nonce-1",
            urlSession: StubURLProtocol.session()
        )

        XCTAssertEqual(attempts, 2)
        XCTAssertEqual(outcome.firstCredential, "vc-1")
        XCTAssertTrue(authorizations.allSatisfy { $0.hasPrefix("DPoP ") }, "\(authorizations)")
    }

    /// A DPoP-bound token with no key to prove possession must fail before the request, not send
    /// `Authorization: DPoP ...` with no proof attached -- which is what the old flag-driven
    /// branch did.
    func testADPoPTokenWithNoKeyFailsRatherThanSendingAnUnprovenHeader() async {
        StubURLProtocol.respond(status: 200, body: #"{"credentials":[{"credential":"vc-1"}]}"#)
        let outcome = await CredentialRequestResolver(keyHandler: StubKeyHandler()).resolve(
            session: session(),
            wallet: WalletIdentity(did: "did:key:zabc"),
            token: token(tokenType: "DPoP"),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            issuer: "did:key:zabc",
            nonce: "c-nonce-1",
            urlSession: StubURLProtocol.session()
        )
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(error.message?.contains("DPoP") == true, error.message ?? "")
    }

    func testABearerTokenSendsBearer() async {
        let (_, headers, _) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil)
        )
        XCTAssertEqual(headers["Authorization"], "Bearer access-1")
        XCTAssertNil(headers["DPoP"])
    }

    /// The encrypted response arrives as `application/jwt`; an exact string compare missed
    /// `application/jwt; charset=utf-8` and fell through to parsing ciphertext as JSON.
    func testAnEncryptedResponseWithACharsetParameterIsStillRecognised() async {
        let (_, _, outcome) = await capture(
            session: session(),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            contentType: "application/jwt; charset=utf-8",
            responseBody: "eyJhbGciOiJFQ0RILUVTIn0..aaa.bbb.ccc"
        )
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        // No decryption key was supplied, so it must say so -- not "not valid JSON", which is what
        // the exact compare produced.
        XCTAssertTrue(error.message?.contains("decryption key") == true, error.message ?? "")
    }

    /// The issuer declares response encryption but the caller passed no key: the member must simply
    /// be absent. It used to put a nil JWK in the dictionary, which made `JSONSerialization` throw
    /// inside a `try?` and sent the request with **no body at all**.
    func testNoResponseKeyMeansNoEncryptionMemberRatherThanAnEmptyBody() async {
        let json = """
        {
          "credentialIssuer": "https://issuer.example.com",
          "declaresAuthorizationServers": true,
          "credentialEndpoint": "https://issuer.example.com/credential",
          "nonceEndPoint": "https://issuer.example.com/nonce",
          "credentialResponseEncryption": {
            "alg_values_supported": ["ECDH-ES"],
            "enc_values_supported": ["A128CBC-HS256"]
          },
          "credentialsSupported": {
            "version": "v2",
            "dataSharing": { "PID": { "format": "dc+sd-jwt", "hasProofTypesSupported": false } }
          }
        }
        """
        let config = try! JSONDecoder().decode(IssuerWellKnownConfiguration.self, from: Data(json.utf8))
        let (body, _, outcome) = await capture(
            session: IssuanceSession(credentialOffer: offer(), issuerConfig: config, authConfig: nil),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil)
        )
        XCTAssertNil(body["credential_response_encryption"])
        XCTAssertNotNil(body["proof"], "the body must not be empty")
        XCTAssertEqual(outcome.firstCredential, "vc-1")
    }

    // MARK: - The key

    /// `generateSecureKey()` is load-or-create, so a second call is a chance to mint a replacement
    /// -- which would change what gets signed and make any logging report a key that signed nothing.
    func testTheBindingKeyIsResolvedExactlyOncePerProof() async {
        let keyHandler = StubKeyHandler()
        _ = await capture(
            session: session(hasProofTypes: false),
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            keyHandler: keyHandler
        )
        XCTAssertEqual(keyHandler.keyRequests, 1)
    }
}
