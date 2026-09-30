import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// Which of §8.2's two proof shapes a request carries.
///
/// The rule: **`jwt` whenever the issuer offers `jwt`**, including when `attestation` is offered
/// beside it; `attestation` only when the issuer accepts nothing else. These tests pin the decision
/// itself — `CredentialRequestTests` covers how each shape is then serialised.
///
/// Mirrors `CredentialProofFactoryTest` in the Android SDK.
final class CredentialProofFactoryTests: XCTestCase {

    private let nonce = "c-nonce-1"

    /// A key attestation carrying `nonce`, which §F.3 requires for an attestation proof.
    /// `carriesNonce` reads the payload without verifying the signature, so a stub suffices.
    private func keyAttestation(carrying nonce: String?) -> String {
        let payload = nonce.map { "{\"nonce\":\"\($0)\"}" } ?? "{}"
        let b64 = Data(payload.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "eyJhbGciOiJFUzI1NiJ9.\(b64).signature"
    }

    private func session(proofTypes: String) throws -> IssuanceSession {
        let offer = try JSONDecoder().decode(
            CredentialOffer.self,
            from: Data(#"{"credentialIssuer":"https://issuer.example.com"}"#.utf8)
        )
        let config = try JSONDecoder().decode(
            IssuerWellKnownConfiguration.self,
            from: Data("""
            {
              "credentialIssuer": "https://issuer.example.com",
              "declaresAuthorizationServers": false,
              "credentialEndpoint": "https://issuer.example.com/credential",
              "credentialsSupported": {
                "version": "v2",
                "dataSharing": {
                  "PID": { "format": "dc+sd-jwt", "types": ["PID"], "proofTypesSupported": \(proofTypes) }
                }
              }
            }
            """.utf8)
        )
        return IssuanceSession(credentialOffer: offer, issuerConfig: config, authConfig: nil)
    }

    private func handler() -> SecureKeyProtocol {
        let key = P256.Signing.PrivateKey()
        return CryptoKitHandler(secureKeyData: SecureKeyData(
            publicKey: key.publicKey.rawRepresentation, privateKey: key.rawRepresentation
        ))
    }

    private func createAll(
        proofTypes: String,
        keyAttestation: String?,
        additional: [SecureKeyProtocol] = []
    ) async throws -> CredentialProofs {
        try await CredentialProofFactory.createAll(
            session: try session(proofTypes: proofTypes),
            wallet: WalletIdentity(did: "did:key:zBinding"),
            keyHandler: handler(),
            additionalKeyHandlers: additional,
            issuer: "did:key:zWallet",
            nonce: nonce,
            subject: .byConfiguration(credentialConfigurationId: "PID", offerCredential: nil),
            keyAttestation: keyAttestation
        )
    }

    /// The rule the SDK is built on: a signed proof of possession wins wherever it is accepted.
    func testJwtWinsWhenTheIssuerOffersBothProofTypes() async throws {
        let proofs = try await createAll(
            proofTypes: #"{"jwt":{},"attestation":{}}"#, keyAttestation: keyAttestation(carrying: nonce)
        )

        guard case let .jwt(list) = proofs else { return XCTFail("expected jwt proofs, got \(proofs)") }
        XCTAssertEqual(list.count, 1)
    }

    /// With no `attestation` on offer there is nothing to choose; the jwt proof is the only shape.
    func testJwtIsUsedWhenTheIssuerOffersOnlyJwt() async throws {
        let proofs = try await createAll(proofTypes: #"{"jwt":{}}"#, keyAttestation: nil)

        guard case .jwt = proofs else { return XCTFail("expected jwt proofs, got \(proofs)") }
    }

    /// ARF TS3 §2.2.2: only then does the key attestation stand as the proof itself.
    func testOnlyAttestationMakesTheKeyAttestationTheProof() async throws {
        let ka = keyAttestation(carrying: nonce)

        let proofs = try await createAll(proofTypes: #"{"attestation":{}}"#, keyAttestation: ka)

        guard case let .attestation(sent) = proofs else {
            return XCTFail("expected an attestation proof, got \(proofs)")
        }
        XCTAssertEqual(sent, ka)
    }

    /// No attestation to send and no jwt proof the issuer would accept: fail before the round trip.
    func testAttestationOnlyWithNoKeyAttestationFailsBeforeTheRequest() async throws {
        do {
            _ = try await createAll(proofTypes: #"{"attestation":{}}"#, keyAttestation: nil)
            XCTFail("expected a proofFailed error")
        } catch let error as CredentialRequestError {
            XCTAssertTrue("\(error)".contains("no key attestation"), "got \(error)")
        }
    }

    /// §F.3: the issuer's current c_nonce lives inside the attestation, and is checked here.
    func testAttestationOnlyWithAStaleNonceFailsBeforeTheRequest() async throws {
        do {
            _ = try await createAll(
                proofTypes: #"{"attestation":{}}"#, keyAttestation: keyAttestation(carrying: "a-stale-nonce")
            )
            XCTFail("expected a proofFailed error")
        } catch let error as CredentialRequestError {
            XCTAssertTrue("\(error)".contains("c_nonce"), "got \(error)")
        }
    }

    /// A batch is one proof per key, each signed by its own; the shape stays `jwt`.
    func testAdditionalKeysMakeABatchOfJwtProofs() async throws {
        let proofs = try await createAll(
            proofTypes: #"{"jwt":{}}"#, keyAttestation: nil, additional: [handler()]
        )

        guard case let .jwt(list) = proofs else { return XCTFail("expected jwt proofs, got \(proofs)") }
        XCTAssertEqual(list.count, 2)
        XCTAssertEqual(Set(list).count, 2, "each key must sign its own proof")
        XCTAssertTrue(proofs.isBatch)
    }
}
