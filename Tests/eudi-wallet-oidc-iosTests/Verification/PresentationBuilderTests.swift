//
//  PresentationBuilderTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
import CryptoKit
import SwiftCBOR
@testable import eudiWalletOidcIos

/// Leg 4: the typed presentation builders. Row numbers refer to the leg 4 matrix in the iOS plan.
final class PresentationBuilderTests: ResponseCharacterisationTestCase {

    private typealias F = VerificationFixtures

    private let familyName = Claim.pathClaim(PathClaim(path: ["org.iso.18013.5.1", "family_name"], id: nil))

    private func inputs(_ request: PresentationRequest, holderKey: SecureKeyProtocol? = nil, hashes: [String: [String]] = [:],
                        sca: Bool = false, authentication: AuthenticationMethods? = nil) -> PresentationInputs {
        PresentationInputs(request: request, holderDid: F.did, holderKey: holderKey ?? walletKeyHandler,
                           transactionDataHashes: hashes, strongCustomerAuthentication: sca, authentication: authentication)
    }

    private func build(_ selected: [SelectedCredential], _ inputs: PresentationInputs) async throws -> [Presentation] {
        try await PresentationBuilder().build(selected, inputs: inputs)
    }

    private func expectError(_ expected: PresentationError, _ block: () async throws -> Void) async {
        do {
            try await block()
            XCTFail("expected \(expected)")
        } catch {
            XCTAssertEqual(error as? PresentationError, expected)
        }
    }

    /// Whether the first document's device signature verifies over `transcript` with `key`.
    private func verifiesDeviceSignature(_ token: String, _ transcript: SessionTranscript, key: P256.Signing.PublicKey,
                                         document: Int = 0, docType: String = F.docType) -> Bool {
        guard case .array(let cose)? = F.decodeCbor(token)?["documents"]?[CBOR.unsignedInt(UInt64(document))]?["deviceSigned"]?["deviceAuth"]?["deviceSignature"],
              cose.count == 4, case .byteString(let protected) = cose[0], case .byteString(let raw) = cose[3],
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
        let payload = buildDeviceAuthenticationBytes(sessionTranscript: transcript.array, docType: docType,
                                                     deviceNameSpacesBytes: encodeEmptyDeviceNameSpaces())
        let toBeSigned = CBOR.array([.utf8String("Signature1"), .byteString(protected), .byteString([]), .byteString(payload)]).encode()
        return key.isValidSignature(signature, for: Data(toBeSigned))
    }

    private func elements(_ token: String, document: Int = 0) -> [String] {
        guard case .map(let nameSpaces)? = F.decodeCbor(token)?["documents"]?[CBOR.unsignedInt(UInt64(document))]?["issuerSigned"]?["nameSpaces"] else { return [] }
        return nameSpaces.values.flatMap { value -> [String] in
            guard case .array(let items) = value else { return [] }
            return items.compactMap { item in
                guard case .tagged(_, .byteString(let bytes)) = item, let decoded = try? CBOR.decode(bytes),
                      case .utf8String(let id)? = decoded["elementIdentifier"] else { return nil }
                return id
            }
        }.sorted()
    }

    // MARK: SD-JWT

    func test4_1KeyBindingJwtCarriesAudienceNonceAndSdHash() async throws {
        let credential = F.sdJwt()
        let presented = try await build([SelectedCredential(entryId: "pid", credential: credential, keyId: "holder")],
                                        inputs(F.dcqlRequest(F.dcqlSdJwt("pid"))))

        XCTAssertEqual(presented.map { $0.format }, [.sdJwt])
        let kb = F.keyBindingJwt(presented[0].token)
        XCTAssertTrue(F.verifies(kb, with: holder.publicKey))
        XCTAssertEqual(JWTParts.header(kb)?["typ"] as? String, "kb+jwt")
        XCTAssertEqual(JWTParts.header(kb)?["alg"] as? String, "ES256")
        let claims = try XCTUnwrap(JWTParts.claims(kb))
        XCTAssertEqual(claims["aud"] as? String, F.clientId)
        XCTAssertEqual(claims["nonce"] as? String, F.nonce)
        XCTAssertEqual(claims["sd_hash"] as? String, SDJWTService.shared.calculateSHA256Hash(inputString: credential))
        XCTAssertNotNil(claims["iat"])
        XCTAssertNil(claims["jti"], "jti only goes with SCA, as before")
    }

    func test4_3AKeyThatCannotSignIsRefused() async {
        await expectError(.keyBindingFailed("pid")) {
            _ = try await self.build([SelectedCredential(entryId: "pid", credential: F.sdJwt(), keyId: "missing")],
                                     self.inputs(F.dcqlRequest(F.dcqlSdJwt("pid"))))
        }
    }

    func test4_4AnEdDsaKeySignsTheKeyBindingJwtWithEdDsa() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let handler = EDDSAKeyHandler(secureKeyData: SecureKeyData(publicKey: key.publicKey.rawRepresentation,
                                                                   privateKey: key.rawRepresentation))
        let presented = try await build([SelectedCredential(entryId: "pid", credential: F.sdJwt())],
                                        inputs(F.dcqlRequest(F.dcqlSdJwt("pid")), holderKey: handler))

        let kb = F.keyBindingJwt(presented[0].token)
        XCTAssertEqual(JWTParts.header(kb)?["alg"] as? String, "EdDSA")
        let parts = kb.split(separator: ".").map(String.init)
        let signature = try XCTUnwrap(Data(b64url: parts[2]))
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: Data("\(parts[0]).\(parts[1])".utf8)))
    }

    func test4_5AnSdJwtWithoutVctUnderAPresentationDefinitionIsPresentedAsAnSdJwt() async throws {
        let credential = F.unsignedJwt(["iss": "https://issuer.example", "given_name": "Alice"]) + "~"
        let params = await respond(F.pexRequest(F.sdJwtDescriptor("pid")), [[credential]])

        let token = try XCTUnwrap(params?["vp_token"] as? String)
        XCTAssertTrue(token.hasPrefix(credential), "previously wrapped inside a W3C presentation")
        XCTAssertTrue(F.verifies(F.keyBindingJwt(token), with: holder.publicKey))
        let submission = try XCTUnwrap(F.object(params?["presentation_submission"]) as? [String: Any])
        let entry = try XCTUnwrap((submission["descriptor_map"] as? [[String: Any]])?.first)
        XCTAssertEqual(entry["path"] as? String, "$")
        XCTAssertEqual(entry["format"] as? String, "vc+sd-jwt")
    }

    func test4_6TransactionDataHashesGoOnlyToTheEntryTheyName() async throws {
        let presented = try await build([SelectedCredential(entryId: "a", credential: F.sdJwt(), keyId: "holder"),
                                         SelectedCredential(entryId: "b", credential: F.sdJwt(), keyId: "holder")],
                                        inputs(F.dcqlRequest(F.dcqlSdJwt("a"), F.dcqlSdJwt("b")), hashes: ["a": ["h1"]]))

        let a = try XCTUnwrap(JWTParts.claims(F.keyBindingJwt(presented[0].token)))
        let b = try XCTUnwrap(JWTParts.claims(F.keyBindingJwt(presented[1].token)))
        XCTAssertEqual(a["transaction_data_hashes"] as? [String], ["h1"])
        XCTAssertEqual(a["transaction_data_hashes_alg"] as? String, "sha-256")
        XCTAssertNil(b["transaction_data_hashes"])
    }

    func test4_7ScaPutsResponseModeJtiAndAmrInTheKeyBindingJwt() async throws {
        let presented = try await build([SelectedCredential(entryId: "pid", credential: F.sdJwt(), keyId: "holder")],
                                        inputs(F.dcqlRequest(F.dcqlSdJwt("pid")), sca: true,
                                               authentication: AuthenticationMethods(inherence: "face")))

        let claims = try XCTUnwrap(JWTParts.claims(F.keyBindingJwt(presented[0].token)))
        XCTAssertEqual(claims["response_mode"] as? String, "direct_post")
        XCTAssertNotNil(claims["jti"])
        XCTAssertEqual(claims["amr"] as? [[String: String]], [["possession": "key_in_local_native_wscd"], ["inherence": "face"]])
    }

    // MARK: mdoc

    func test4_9AnMdocUnderDcqlIsSignedOverTheOpenId4VpTranscript() async throws {
        let request = F.dcqlRequest(F.dcqlMdoc("mdl", claims: [familyName]))
        let presented = try await build([SelectedCredential(entryId: "mdl", credential: F.mdoc(deviceKey: holder.publicKey), keyId: "holder")],
                                        inputs(request))

        let transcript = SessionTranscript.openId4Vp(clientId: F.clientId, nonce: F.nonce, responseUri: F.responseUri,
                                                     encryptionKeyThumbprint: nil)
        XCTAssertTrue(verifiesDeviceSignature(presented[0].token, transcript, key: holder.publicKey))
    }

    func test4_10TheDcApiResponseModeUsesTheDcApiHandoverWithoutTheOriginPrefix() async throws {
        var request = F.dcqlRequest(F.dcqlMdoc("mdl", claims: [familyName]), responseMode: "dc_api")
        request.clientId = "origin:https://rp.example"
        let presented = try await build([SelectedCredential(entryId: "mdl", credential: F.mdoc(deviceKey: holder.publicKey), keyId: "holder")],
                                        inputs(request))

        let transcript = SessionTranscript.dcApi(origin: "https://rp.example", nonce: F.nonce, encryptionKeyThumbprint: nil)
        XCTAssertTrue(verifiesDeviceSignature(presented[0].token, transcript, key: holder.publicKey))
    }

    func test4_11APresentationDefinitionUsesTheAnnexBTranscript() async throws {
        let presented = try await build([SelectedCredential(entryId: "mdl", credential: F.mdoc(deviceKey: holder.publicKey), keyId: "holder")],
                                        inputs(F.pexRequest(F.mdocDescriptor("mdl"))))

        let transcript = SessionTranscript.annexB(clientId: F.clientId, nonce: F.nonce, responseUri: F.responseUri)
        XCTAssertTrue(verifiesDeviceSignature(presented[0].token, transcript, key: holder.publicKey))
    }

    func test4_12AnMdocQueryWithNoClaimsDisclosesEveryElement() async throws {
        var entry = F.dcqlMdoc("mdl")
        entry.claims = nil
        let credential = F.mdoc(deviceKey: holder.publicKey, nameSpaces: ["org.iso.18013.5.1": ["family_name": "Doe", "given_name": "Jo"]])
        let presented = try await build([SelectedCredential(entryId: "mdl", credential: credential, keyId: "holder")],
                                        inputs(F.dcqlRequest(entry)))

        XCTAssertEqual(elements(presented[0].token), ["family_name", "given_name"])
    }

    func test4_13AnMdocWithNoUsableKeyIsRefused() async {
        await expectError(.noKey("mdl")) {
            _ = try await self.build([SelectedCredential(entryId: "mdl", credential: F.mdoc(deviceKey: self.holder.publicKey))],
                                     self.inputs(F.dcqlRequest(F.dcqlMdoc("mdl", claims: [self.familyName]))))
        }
    }

    func test4_14TwoMdocsUnderAPresentationDefinitionShareOneDeviceResponse() async throws {
        let params = await respond(F.pexRequest(F.mdocDescriptor("a"), F.mdocDescriptor("b")),
                                   [[F.mdoc(deviceKey: holder.publicKey)], [F.mdoc(deviceKey: holder.publicKey)]])

        let token = try XCTUnwrap(params?["vp_token"] as? String)
        guard case .array(let documents)? = F.decodeCbor(token)?["documents"] else { return XCTFail("no documents") }
        XCTAssertEqual(documents.count, 2)
        let submission = try XCTUnwrap(F.object(params?["presentation_submission"]) as? [String: Any])
        let entries = try XCTUnwrap(submission["descriptor_map"] as? [[String: Any]])
        XCTAssertEqual(entries.map { $0["id"] as? String }, ["a", "b"])
        XCTAssertEqual(entries.map { $0["path"] as? String }, ["$", "$"])
    }

    func test4_15EachCredentialInAnMdocEntryDisclosesOnlyTheNamedElements() async throws {
        let first = F.mdoc(deviceKey: holder.publicKey, nameSpaces: ["org.iso.18013.5.1": ["family_name": "Doe", "given_name": "Jo"]])
        let second = F.mdoc(deviceKey: holder.publicKey, nameSpaces: ["org.iso.18013.5.1": ["family_name": "Roe", "birth_date": "1990"]])
        let presented = try await build([SelectedCredential(entryId: "mdl", credential: first, keyId: "holder"),
                                         SelectedCredential(entryId: "mdl", credential: second, keyId: "holder")],
                                        inputs(F.dcqlRequest(F.dcqlMdoc("mdl", claims: [familyName]))))

        XCTAssertEqual(presented.count, 2)
        XCTAssertEqual(elements(presented[0].token), ["family_name"])
        XCTAssertEqual(elements(presented[1].token), ["family_name"])
    }

    // MARK: W3C

    func test4_16AW3CCredentialUnderDcqlIsSignedWithTheHolderKey() async throws {
        let presented = try await build([SelectedCredential(entryId: "vc", credential: F.jwtVc())], inputs(F.dcqlRequest(F.dcqlJwt("vc"))))

        XCTAssertEqual(presented.map { $0.format }, [.w3cVp])
        XCTAssertTrue(F.verifies(presented[0].token, with: walletKey.publicKey))
        let claims = try XCTUnwrap(JWTParts.claims(presented[0].token))
        XCTAssertEqual(claims["iss"] as? String, F.did)
        XCTAssertEqual((claims["vp"] as? [String: Any])?["holder"] as? String, F.did)
        XCTAssertEqual(claims["aud"] as? String, F.clientId)
    }

    func test4_17SeveralW3CCredentialsUnderAPresentationDefinitionAreAggregatedWhereTheFirstWas() async throws {
        let request = F.pexRequest(F.jwtDescriptor("a"), F.sdJwtDescriptor("b"), F.jwtDescriptor("c"))
        let presented = try await build([SelectedCredential(entryId: "a", credential: F.jwtVc()),
                                         SelectedCredential(entryId: "b", credential: F.sdJwt(), keyId: "holder"),
                                         SelectedCredential(entryId: "c", credential: F.jwtVc())], inputs(request))

        XCTAssertEqual(presented.map { $0.format }, [.w3cVp, .sdJwt])
        XCTAssertEqual(presented[0].entryIds, ["a", "c"])
        let definition = try VerificationService.processPresentationDefinition(request.presentationDefinition)
        let map = PresentationSubmissionBuilder().build(presented, definition: definition).descriptorMap
        XCTAssertEqual(map.map { $0.id }, ["a", "c", "b"])
        XCTAssertEqual(map.map { $0.path }, ["$[0]", "$[0]", "$[1]"])
        XCTAssertEqual(map.map { $0.pathNested?.path }, ["$[0].vp.verifiableCredential[0]", "$[0].vp.verifiableCredential[1]", nil])
    }

    func test4_18AW3CCredentialsOwnKeyIdIsNotUsed() async throws {
        let presented = try await build([SelectedCredential(entryId: "vc", credential: F.jwtVc(), keyId: "holder")],
                                        inputs(F.dcqlRequest(F.dcqlJwt("vc"))))

        XCTAssertTrue(F.verifies(presented[0].token, with: walletKey.publicKey))
        XCTAssertFalse(F.verifies(presented[0].token, with: holder.publicKey))
    }

    // MARK: Inputs

    func test4_20ABlankCredentialIsRefusedByTheNewApi() async {
        await expectError(.unsupportedFormat("pid")) {
            _ = try await self.build([SelectedCredential(entryId: "pid", credential: " ")], self.inputs(F.dcqlRequest(F.dcqlSdJwt("pid"))))
        }
    }

    func test4_21FewerKeyIdsThanCredentialsFallBackToTheHolderKeyInsteadOfCrashing() async throws {
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("pid")), [[F.sdJwt(), F.sdJwt()]], keyIds: [["holder"]])

        let presented = try XCTUnwrap(F.object(params?["vp_token"]) as? [String: Any])["pid"] as? [String]
        XCTAssertEqual(presented?.count, 2)
        XCTAssertTrue(F.verifies(F.keyBindingJwt(presented?[0] ?? ""), with: holder.publicKey))
        XCTAssertTrue(F.verifies(F.keyBindingJwt(presented?[1] ?? ""), with: walletKey.publicKey))

        let pex = await respond(F.pexRequest(F.sdJwtDescriptor("pid")), [[F.sdJwt()]], keyIds: [])
        XCTAssertNotNil(pex?["vp_token"] as? String)
    }

    func testTheSessionTranscriptFunctionsKeepTheirOutput() {
        let viaFunction = buildSessionTranscriptForOpenID4VP(clientId: F.clientId, nonce: F.nonce, responseUri: F.responseUri)
        let viaType = SessionTranscript.openId4Vp(clientId: F.clientId, nonce: F.nonce, responseUri: F.responseUri, encryptionKeyThumbprint: nil)
        XCTAssertEqual(viaFunction.bytes, viaType.bytes)

        let dcApi = buildSessionTranscriptForOpenID4VP(clientId: "https://rp.example", nonce: F.nonce, responseMode: "dc_api")
        XCTAssertEqual(dcApi.bytes, SessionTranscript.dcApi(origin: "https://rp.example", nonce: F.nonce, encryptionKeyThumbprint: nil).bytes)
    }
}
