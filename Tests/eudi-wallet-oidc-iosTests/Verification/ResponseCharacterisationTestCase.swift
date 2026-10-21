//
//  ResponseCharacterisationTestCase.swift
//  eudiWalletOidcIosTests
//

import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// Base for the response characterisation tests. Routes the stored key ids the builders sign with
/// to software keys, and calls the entry point the wallet uses
/// (`AuthorisationResponseHandler.prepareAuthorisationResponse`).
class ResponseCharacterisationTestCase: XCTestCase {

    /// The credential's bound key, stored under key id `holder`.
    let holder = SoftwareKey()
    /// Further stored keys by key id; an id not found here resolves to a key that cannot sign.
    var storedKeys: [String: SoftwareKey] = [:]
    /// The wallet's DID key, passed to the handler as `keyHandler`.
    let walletKey = P256.Signing.PrivateKey()

    private var originalPresentationKey: ((String) -> SecureKeyProtocol)!

    override func setUp() {
        super.setUp()
        storedKeys["holder"] = holder
        originalPresentationKey = SecureEnclaveHandler.presentationKey
        SecureEnclaveHandler.presentationKey = { [unowned self] keyId -> SecureKeyProtocol in
            if let key = self.storedKeys[keyId] { return key }
            return UnusableKey()
        }
    }

    override func tearDown() {
        SecureEnclaveHandler.presentationKey = originalPresentationKey
        super.tearDown()
    }

    var walletKeyHandler: SecureKeyProtocol {
        CryptoKitHandler(secureKeyData: SecureKeyData(publicKey: walletKey.publicKey.rawRepresentation,
                                                      privateKey: walletKey.rawRepresentation))
    }

    func respond(_ request: PresentationRequest, _ credentials: [[String]], keyIds: [[String]]? = nil,
                 isSca: Bool = false, inherence: String? = nil, knowledge: String? = nil) async -> [String: Any]? {
        await AuthorisationResponseHandler().prepareAuthorisationResponse(
            credentialsList: credentials,
            presentationRequest: request,
            did: VerificationFixtures.did,
            keyHandler: walletKeyHandler,
            isSca: isSca,
            keyIds: keyIds ?? credentials.map { $0.map { _ in "holder" } },
            amrInherenceFactor: inherence,
            amrKnowledgeFactor: knowledge)
    }
}
