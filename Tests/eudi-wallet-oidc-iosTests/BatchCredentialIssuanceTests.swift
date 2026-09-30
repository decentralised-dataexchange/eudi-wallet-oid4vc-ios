import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// Batch credential issuance (OpenID4VCI 1.0 §8.2, §12.2.4): the issuer's
/// batch_size and the proofs of a batch request. Same cases as Android's
/// BatchCredentialIssuanceTest, plus the proofs themselves.
final class BatchCredentialIssuanceTests: XCTestCase {

    func testBatchSizeIsReadFrom1_0IssuerMetadata() throws {
        let json = #"{"credential_issuer":"https://issuer.example","batch_credential_issuance":{"batch_size":5}}"#
        let response = try JSONDecoder().decode(IssuerWellKnownConfigurationResponseV2.self, from: Data(json.utf8))
        XCTAssertEqual(IssuerWellKnownConfiguration(from: response).batchCredentialIssuance?.batchSize, 5)
    }

    func testMetadataWithoutBatchSupportHasNoBatchSize() throws {
        let json = #"{"credential_issuer":"https://issuer.example"}"#
        let response = try JSONDecoder().decode(IssuerWellKnownConfigurationResponseV2.self, from: Data(json.utf8))
        XCTAssertNil(IssuerWellKnownConfiguration(from: response).batchCredentialIssuance)
    }

    func testTheBatchSizeSurvivesTheStoredConfiguration() throws {
        let json = #"{"credential_issuer":"https://issuer.example","batch_credential_issuance":{"batch_size":3}}"#
        let config = IssuerWellKnownConfiguration(from: try JSONDecoder().decode(IssuerWellKnownConfigurationResponseV2.self, from: Data(json.utf8)))
        let stored = try JSONDecoder().decode(IssuerWellKnownConfiguration.self, from: JSONEncoder().encode(config))
        XCTAssertEqual(stored.batchCredentialIssuance?.batchSize, 3)
    }

    /// Moved from `IssueService.batchProofs` to `CredentialProofFactory.createAll`, which also
    /// generates the first proof rather than being handed one — so all three keys are checked.
    func testEveryKeySignsItsOwnProofWithTheSameNonceAndAudience() async throws {
        let offer = try JSONDecoder().decode(CredentialOffer.self, from: Data(#"{"credentialIssuer":"https://issuer.example"}"#.utf8))
        // `declaresAuthorizationServers` is a non-optional Bool and a synthesised Decodable ignores
        // property defaults, so it has to be present.
        let config = try JSONDecoder().decode(
            IssuerWellKnownConfiguration.self,
            from: Data(#"{"declaresAuthorizationServers":false}"#.utf8)
        )
        let keys = (0..<3).map { _ in P256.Signing.PrivateKey() }
        let handlers: [SecureKeyProtocol] = keys.map {
            CryptoKitHandler(secureKeyData: SecureKeyData(publicKey: $0.publicKey.rawRepresentation, privateKey: $0.rawRepresentation))
        }

        let proofs = try await CredentialProofFactory.createAll(
            session: IssuanceSession(credentialOffer: offer, issuerConfig: config, authConfig: nil),
            wallet: WalletIdentity(did: "did:key:zWallet"),
            keyHandler: handlers[0],
            additionalKeyHandlers: Array(handlers.dropFirst()),
            issuer: "did:key:zWallet",
            nonce: "n-1",
            subject: .legacyFormat(format: nil)
        )

        guard case let .jwt(list) = proofs else { return XCTFail("expected jwt proofs, got \(proofs)") }
        XCTAssertEqual(list.count, 3)
        XCTAssertTrue(proofs.isBatch)
        XCTAssertEqual(Set(list).count, 3, "each key must sign its own proof")

        for (index, proof) in list.enumerated() {
            let parts = proof.split(separator: ".").map(String.init)
            let claims = try XCTUnwrap(try JSONSerialization.jsonObject(with: try XCTUnwrap(Self.b64url(parts[1]))) as? [String: Any])
            XCTAssertEqual(claims["nonce"] as? String, "n-1")
            XCTAssertEqual(claims["aud"] as? String, offer.credentialIssuer ?? "")
            XCTAssertEqual(claims["iss"] as? String, "did:key:zWallet")
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: try XCTUnwrap(Self.b64url(parts[2])))
            XCTAssertTrue(
                keys[index].publicKey.isValidSignature(signature, for: Data("\(parts[0]).\(parts[1])".utf8)),
                "proof \(index) must be signed by its own key"
            )
        }
    }

    private static func b64url(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        return Data(base64Encoded: b)
    }
}
