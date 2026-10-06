import XCTest
@testable import eudiWalletOidcIos

/// key_attestations_required in the issuer metadata (OID4VCI 12.2.4, ARF TS3
/// 2.2.2.2): which proof type it is read from, and when the binding key has to
/// be hardware-backed.
final class KeyAttestationRequirementTests: XCTestCase {

    private func config(proofTypes: String) throws -> IssuerWellKnownConfiguration {
        let json = """
        {"credential_issuer":"https://issuer.example",
         "credential_configurations_supported":{
           "LegalPersonId":{"format":"dc+sd-jwt","vct":"LegalPersonId",
             "cryptographic_binding_methods_supported":["jwk"],
             "proof_types_supported":\(proofTypes)}}}
        """
        let response = try JSONDecoder().decode(IssuerWellKnownConfigurationResponseV2.self, from: Data(json.utf8))
        return IssuerWellKnownConfiguration(from: response)
    }

    private let highUnderJwt = #"{"jwt":{"proof_signing_alg_values_supported":["ES256"],"key_attestations_required":{"key_storage":["iso_18045_high"]}}}"#
    private let highUnderAttestationOnly = #"{"attestation":{"proof_signing_alg_values_supported":["ES256"],"key_attestations_required":{"key_storage":["iso_18045_high"],"user_authentication":["iso_18045_high"]}}}"#
    private let moderateUnderJwt = #"{"jwt":{"proof_signing_alg_values_supported":["ES256"],"key_attestations_required":{"key_storage":["iso_18045_moderate"]}}}"#
    private let unconstrainedRequirement = #"{"jwt":{"proof_signing_alg_values_supported":["ES256"],"key_attestations_required":{}}}"#
    private let noRequirement = #"{"jwt":{"proof_signing_alg_values_supported":["ES256"]}}"#

    // --- which proof type carries the requirement -------------------------

    func testRequirementIsReadFromTheJwtProofType() throws {
        let cfg = try config(proofTypes: highUnderJwt)
        XCTAssertTrue(KeyAttestationService.isRequired(issuerConfig: cfg, type: "LegalPersonId"))
        XCTAssertEqual(cfg.credentialsSupported?.dataSharing?["LegalPersonId"]?.keyStorage, ["iso_18045_high"])
    }

    /// TS3 2.2.2: an attestation-only issuer lists `attestation` without `jwt`.
    /// Its requirement was missed, so the wallet sent a software-tier KA.
    func testRequirementIsReadFromAnAttestationOnlyIssuer() throws {
        let cfg = try config(proofTypes: highUnderAttestationOnly)
        XCTAssertTrue(KeyAttestationService.isRequired(issuerConfig: cfg, type: "LegalPersonId"))
        XCTAssertEqual(cfg.credentialsSupported?.dataSharing?["LegalPersonId"]?.keyStorage, ["iso_18045_high"])
        XCTAssertTrue(KeyAttestationService.isAttestationOnly(cfg.credentialsSupported?.dataSharing?["LegalPersonId"]))
        XCTAssertTrue(KeyAttestationService.requiresHardwareKeyStorage(issuerConfig: cfg, type: "LegalPersonId"))
    }

    // --- when the hardware tier is needed ---------------------------------

    func testAnyAcceptedLevelNeedsAHardwareBackedKey() throws {
        XCTAssertTrue(KeyAttestationService.requiresHardwareKeyStorage(issuerConfig: try config(proofTypes: highUnderJwt), type: "LegalPersonId"))
        XCTAssertTrue(KeyAttestationService.requiresHardwareKeyStorage(issuerConfig: try config(proofTypes: moderateUnderJwt), type: "LegalPersonId"))
    }

    /// OID4VCI 12.2.4: an empty requirement object asks for a KA with no constraints.
    func testAnUnconstrainedRequirementStillWantsAKaButNotHardware() throws {
        let cfg = try config(proofTypes: unconstrainedRequirement)
        XCTAssertTrue(KeyAttestationService.isRequired(issuerConfig: cfg, type: "LegalPersonId"))
        XCTAssertFalse(KeyAttestationService.requiresHardwareKeyStorage(issuerConfig: cfg, type: "LegalPersonId"))
    }

    func testNoRequirementNeedsNoHardware() throws {
        let cfg = try config(proofTypes: noRequirement)
        XCTAssertFalse(KeyAttestationService.isRequired(issuerConfig: cfg, type: "LegalPersonId"))
        XCTAssertFalse(KeyAttestationService.requiresHardwareKeyStorage(issuerConfig: cfg, type: "LegalPersonId"))
        XCTAssertFalse(KeyAttestationService.requiresHardwareKeyStorage(issuerConfig: cfg, type: "Unknown"))
        XCTAssertFalse(KeyAttestationService.requiresHardwareKeyStorage(issuerConfig: nil, type: "LegalPersonId"))
    }

    /// The configuration is decoded back out of stored credential records.
    func testTheAcceptedLevelsSurviveTheStoredConfiguration() throws {
        let cfg = try config(proofTypes: highUnderAttestationOnly)
        let stored = try JSONDecoder().decode(IssuerWellKnownConfiguration.self, from: JSONEncoder().encode(cfg))
        XCTAssertEqual(stored.credentialsSupported?.dataSharing?["LegalPersonId"]?.keyStorage, ["iso_18045_high"])
    }
}
