//
//  File.swift
//
//
//  Created by iGrant on 04/12/24.
//
import Foundation
import DeviceCheck
import CryptoKit
@available(iOS 14.0, *)
public class WalletUnitAttestationService {
    
    public init() {}
    var baseURL = ""

    /// The wallet-provider registration profile that yields an ARF TS3 WIA
    /// (x5c identity + client_status). Mirrors Android's TS3_PROFILE.
    public static let ts3Profile = "ts3"
    
    /// `keyHandler`, when given, is the cnf key the attestation is bound to (so the
    /// wallet unit keeps one client_id); otherwise the App Attest key id's Secure
    /// Enclave key is used, as before.
    ///
    /// The App Attest key is the device key of the wallet unit. The first
    /// request to a wallet provider generates a new key and attests it; every
    /// later request sends an assertion of the same key. Both sign
    /// SHA-256(request binding), which ties the evidence to the nonce and the
    /// cnf key (``BatchRequestHash/requestBinding(nonce:thumbprint:)``). When
    /// the key is lost or its assertion is refused, a new wallet unit is
    /// registered with a new key, once. Requests run one after the other,
    /// because the assertion counter must increase.
    public func initiateWalletUnitAttestation(walletProviderUrl: String, profile: String? = nil, keyHandler inputKeyHandler: SecureKeyProtocol? = nil) async throws -> (String, WalletUnitAttestationResponse?) {
        try await WalletUnitRequestQueue.shared.run {
            try await self.requestWalletUnitAttestation(walletProviderUrl: walletProviderUrl, profile: profile, keyHandler: inputKeyHandler)
        }
    }

    private func requestWalletUnitAttestation(walletProviderUrl: String, profile: String?, keyHandler inputKeyHandler: SecureKeyProtocol?) async throws -> (String, WalletUnitAttestationResponse?) {
        baseURL = walletProviderUrl
        let service = DCAppAttestService.shared

        if let keyId = registeredKeyId(walletProviderUrl: walletProviderUrl) {
            let keyHandler = inputKeyHandler ?? SecureEnclaveHandler(keyID: keyId)
            // A missing nonce or an unsigned client assertion says nothing about
            // the wallet unit: throw and keep the registration.
            let prepared = try await prepare(keyHandler: keyHandler)
            do {
                let assertion = try await AppAttestRetry.assertion(service: service, keyId: keyId, clientDataHash: prepared.clientDataHash)
                let response = await processWalletUnitAttestationRequest(
                    attestation: assertion.base64URLEncodedString(),
                    nonce: prepared.nonce,
                    keyId: keyId,
                    clientAssertion: prepared.clientAssertion,
                    profile: profile
                )
                guard let response else {
                    // No answer (offline, timeout): not a refusal, keep the registration.
                    throw NSError(domain: "WalletUnitAttestation", code: -1, userInfo: [NSLocalizedDescriptionKey: "No answer from the wallet provider"])
                }
                if response.walletUnitAttestation?.isEmpty == false {
                    return (prepared.clientAssertion, response)
                }
                print("Wallet unit request with an assertion was refused - registering a new wallet unit")
            } catch let error as NSError where error.domain == "WalletUnitAttestation" {
                throw error
            } catch {
                print("Wallet unit assertion failed (\(error)) - registering a new wallet unit")
            }
            clearRegisteredKeyId()
        }

        // Registration: a new App Attest key, attested once.
        let keyId = try await generateKeyId()
        storeKeyIdInKeychain(keyId)
        let keyHandler = inputKeyHandler ?? SecureEnclaveHandler(keyID: keyId)
        let prepared = try await prepare(keyHandler: keyHandler)
        let attestation = try await AppAttestRetry.attestExistingKey(service: service, keyId: keyId, clientDataHash: prepared.clientDataHash)
        let response = await processWalletUnitAttestationRequest(
            attestation: Self.base64URL(fromBase64: attestation),
            nonce: prepared.nonce,
            keyId: keyId,
            clientAssertion: prepared.clientAssertion,
            profile: profile
        )
        if response?.walletUnitAttestation?.isEmpty == false {
            storeRegisteredKeyId(keyId, walletProviderUrl: walletProviderUrl)
        }
        return (prepared.clientAssertion, response)
    }

    private struct PreparedRequest {
        let nonce: String
        let clientAssertion: String
        let clientDataHash: Data
    }

    /// A new nonce, the client assertion signed by the cnf key and the
    /// clientDataHash = SHA-256(UTF-8(request binding)).
    private func prepare(keyHandler: SecureKeyProtocol) async throws -> PreparedRequest {
        let nonceResponse = await fetchWalletProviderNonce(url: "\(baseURL)/nonce")
        guard let nonce = nonceResponse?.nonce ?? nonceResponse?.cNonce, !nonce.isEmpty else {
            throw NSError(domain: "WalletUnitAttestation", code: -1, userInfo: [NSLocalizedDescriptionKey: "No nonce from the wallet provider"])
        }
        guard let jwk = keyHandler.getJWK(publicKey: keyHandler.generateSecureKey()?.publicKey ?? Data()),
              let thumbprint = JWKThumbprint.rfc7638(of: jwk) else {
            throw NSError(domain: "WalletUnitAttestation", code: -1, userInfo: [NSLocalizedDescriptionKey: "The cnf key has no EC JWK"])
        }
        let clientAssertion = await createClientAssertion(keyHandler: keyHandler)
        guard !clientAssertion.isEmpty else {
            throw NSError(domain: "WalletUnitAttestation", code: -1, userInfo: [NSLocalizedDescriptionKey: "The client assertion could not be signed"])
        }
        let binding = BatchRequestHash.requestBinding(nonce: nonce, thumbprint: thumbprint)
        return PreparedRequest(nonce: nonce, clientAssertion: clientAssertion, clientDataHash: Data(SHA256.hash(data: Data(binding.utf8))))
    }

    static func base64URL(fromBase64 value: String) -> String {
        Data(base64Encoded: value)?.base64URLEncodedString() ?? value
    }

    private static let registeredUnitAccount = "AppAttestationRegisteredUnit"

    /// The App Attest key id registered with `walletProviderUrl`, when it is
    /// still the key in ``retrieveKeyIdFromKeychain()``.
    func registeredKeyId(walletProviderUrl: String) -> String? {
        guard let stored = AppAttestKeyStore.pendingKeyId(account: Self.registeredUnitAccount),
              let separator = stored.lastIndex(of: " ") else { return nil }
        let url = String(stored[..<separator])
        let keyId = String(stored[stored.index(after: separator)...])
        guard url == walletProviderUrl, !keyId.isEmpty, keyId == retrieveKeyIdFromKeychain() else { return nil }
        return keyId
    }

    func storeRegisteredKeyId(_ keyId: String, walletProviderUrl: String) {
        AppAttestKeyStore.storePendingKeyId(walletProviderUrl + " " + keyId, account: Self.registeredUnitAccount)
    }

    func clearRegisteredKeyId() {
        AppAttestKeyStore.clearPendingKeyId(account: Self.registeredUnitAccount)
    }
    
    func storeKeyIdInKeychain(_ keyId: String) {
        let keychainQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "AppAttestationKeyId",
            kSecValueData as String: keyId.data(using: .utf8)!
        ]
        
        SecItemDelete(keychainQuery as CFDictionary)
        
        // Add the new keyId
        let status = SecItemAdd(keychainQuery as CFDictionary, nil)
        
        if status == errSecSuccess {
            print("KeyId successfully stored in Keychain.")
        } else {
            print("Failed to store KeyId in Keychain: \(status)")
        }
    }
    
    public func retrieveKeyIdFromKeychain() -> String? {
        let keychainQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "AppAttestationKeyId",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(keychainQuery as CFDictionary, &dataTypeRef)
        
        if status == errSecSuccess, let data = dataTypeRef as? Data {
            return String(data: data, encoding: .utf8)
        } else {
            print("Failed to retrieve KeyId from Keychain: \(status)")
            return nil
        }
    }
    
    /// Batch registration: one App Attest check, `keyHandlers.count` wallet
    /// instance attestations. Each client assertion is signed by its own key and
    /// carries that key in cnf.jwk; all share one client_id (`clientId`,
    /// defaulting to the did:key of key 0). The App Attest challenge is
    /// `BatchRequestHash` over the cnf keys, which the wallet provider
    /// recomputes. The result is index-aligned with the keys; each attestation
    /// is single use.
    ///
    /// Returns nil only when the flow failed before a request could be made
    /// (App Attest, signing). An HTTP error is returned in the result
    /// (httpCode / errorBody, no attestations) so the caller can fall back to
    /// the single endpoint.
    public func initiateBatchWalletUnitAttestation(
        walletProviderUrl: String,
        keyHandlers: [SecureKeyProtocol],
        profile: String? = nil,
        clientId: String? = nil
    ) async -> BatchWalletAttestationResult? {
        guard !keyHandlers.isEmpty else { return nil }
        baseURL = walletProviderUrl
        do {
            var dids: [String] = []
            var jwks: [[String: Any]] = []
            for handler in keyHandlers {
                guard let jwk = handler.getJWK(publicKey: handler.generateSecureKey()?.publicKey ?? Data()) else { return nil }
                jwks.append(jwk)
                dids.append(await createDIDforWUA(keyHandler: handler))
            }
            let sharedClientId = clientId ?? dids[0]

            let nonceResponse = await fetchWalletProviderNonce(url: "\(baseURL)/nonce")
            let nonce = nonceResponse?.nonce ?? nonceResponse?.cNonce ?? ""

            // The batch hash binds the App Attest verdict to the cnf keys, not to the nonce.
            let requestHash = BatchRequestHash.compute(jwks: jwks)
            let hash = Data(SHA256.hash(data: Data(requestHash.utf8)))
            let (keyId, attestation) = try await attestRegistrationKey(hash: hash)

            var assertions: [String] = []
            for handler in keyHandlers {
                let assertion = await createClientAssertion(aud: baseURL, keyHandler: handler, clientId: sharedClientId)
                if assertion.isEmpty { return nil }
                assertions.append(assertion)
            }

            let wire = await processBatchWalletUnitAttestationRequest(
                attestation: attestation,
                nonce: nonce,
                keyId: keyId,
                clientAssertions: assertions,
                profile: profile
            )
            let returned = wire.body?.walletUnitAttestations ?? []
            if returned.count != keyHandlers.count {
                print("Batch registration: requested \(keyHandlers.count) attestations, got \(returned.count) (HTTP \(wire.httpCode.map(String.init) ?? "-"))")
            }
            return BatchWalletAttestationResult(
                clientId: sharedClientId,
                requestHash: requestHash,
                httpCode: wire.httpCode,
                errorBody: wire.errorBody,
                credentialOffer: wire.body?.credentialOffer,
                credentialIssuer: wire.body?.credentialIssuer,
                units: keyHandlers.indices.map { i in
                    BatchWalletUnit(
                        index: i,
                        did: dids[i],
                        keyHandler: keyHandlers[i],
                        clientAssertion: assertions[i],
                        walletUnitAttestation: i < returned.count ? returned[i] : nil
                    )
                }
            )
        } catch {
            print("Batch registration failed: \(error)")
            return nil
        }
    }

    /// GET the wallet provider's nonce document ({service}/nonce or
    /// {service}/wallet-provider/nonce): `nonce` goes with the App Attest
    /// check, `c_nonce` is the key-attestation challenge.
    public func fetchWalletProviderNonce(url: String) async -> NonceResponse? {
        guard let url = URL(string: url) else { return nil }
        do {
            let (data, response) = try await NetworkLogger.send(url: url, tag: "wallet-provider-nonce")
            guard let status = (response as? HTTPURLResponse)?.statusCode, (200..<300).contains(status) else { return nil }
            return try JSONDecoder().decode(NonceResponse.self, from: data)
        } catch {
            print("Nonce fetch failed: \(error)")
            return nil
        }
    }

    /// Attests the App Attest registration key from the Keychain against `hash`.
    /// A key can be attested only once, so on failure a new key is minted,
    /// stored and attested, as the single registration does.
    private func attestRegistrationKey(hash: Data) async throws -> (keyId: String, attestation: String) {
        var keyId = retrieveKeyIdFromKeychain() ?? ""
        if keyId.isEmpty {
            keyId = try await generateKeyId()
            storeKeyIdInKeychain(keyId)
        }
        do {
            return (keyId, try await generateDeviceIntegrityToken(keyId: keyId, hash: hash))
        } catch {
            print("Attestation with keyId \(keyId) failed, regenerating key ID...")
            keyId = try await generateKeyId()
            storeKeyIdInKeychain(keyId)
            return (keyId, try await generateDeviceIntegrityToken(keyId: keyId, hash: hash))
        }
    }

    private struct BatchWire {
        let httpCode: Int?
        let body: BatchCredentialOfferResponse?
        let errorBody: String?
    }

    /// POST {baseUrl}/wallet-unit/request/batch; keeps the HTTP status for the caller.
    private func processBatchWalletUnitAttestationRequest(attestation: String, nonce: String, keyId: String, clientAssertions: [String], profile: String?) async -> BatchWire {
        guard let url = URL(string: "\(baseURL)/wallet-unit/request/batch") else { return BatchWire(httpCode: nil, body: nil, errorBody: "invalid url") }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(attestation, forHTTPHeaderField: "X-Wallet-Unit-Integrity-Token")
        request.setValue("ios", forHTTPHeaderField: "X-Wallet-Unit-Platform")
        request.setValue(nonce, forHTTPHeaderField: "X-Wallet-Unit-Nonce")
        request.setValue(keyId, forHTTPHeaderField: "X-Wallet-Unit-KeyID")
        var bodyDict: [String: Any] = [
            "client_assertions": clientAssertions,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ]
        if let profile = profile, !profile.isEmpty {
            bodyDict["profile"] = profile
        }
        request.httpBody = try? JSONSerialization.data(withJSONObject: bodyDict)
        do {
            let (data, response) = try await NetworkLogger.send(request, tag: "wallet-unit-attestation-batch")
            let status = (response as? HTTPURLResponse)?.statusCode
            if let status = status, (200..<300).contains(status) {
                return BatchWire(httpCode: status, body: try? JSONDecoder().decode(BatchCredentialOfferResponse.self, from: data), errorBody: nil)
            }
            return BatchWire(httpCode: status, body: nil, errorBody: String(data: data, encoding: .utf8))
        } catch {
            return BatchWire(httpCode: nil, body: nil, errorBody: error.localizedDescription)
        }
    }

    public func createDIDforWUA(keyHandler: SecureKeyProtocol) async -> String {
           guard let jwk = keyHandler.getJWK(publicKey: keyHandler.generateSecureKey()?.publicKey ?? Data()) else { return ""}
           let did = await DidService.shared.createDID(jwk: jwk) ?? ""
           return did
       }
    
    /// `clientId`, when given, is the wallet unit's identity for iss / sub / client_id.
    /// In a batch every assertion shares one client_id while kid and cnf name the
    /// signing key.
    public func createClientAssertion(aud: String = "", keyHandler: SecureKeyProtocol, clientId: String? = nil) async -> String {
        let jwk = keyHandler.getJWK(publicKey: keyHandler.generateSecureKey()?.publicKey ?? Data())
        let did = await createDIDforWUA(keyHandler: keyHandler)
        let subject = clientId ?? did
        let header = ([
            "alg": "ES256",
            "kid": "\(did)#\(did.replacingOccurrences(of: "did:key:", with: ""))",
            "typ": "JWT"
        ] as [String: Any]).toString() ?? ""
        let now = Int(Date().timeIntervalSince1970)
        let exp = now + 3600
        let jti = UUID().uuidString
        let payload = ([
            "aud": aud ?? baseURL,
            "client_id": subject,
            "cnf": ["jwk": jwk],
            "exp": exp,
            "iat": now,
            "iss": subject,
            "jti": "urn:uuid:\(jti)",
            "sub": subject
        ] as [String: Any]).toString() ?? ""
        let headerData = Data(header.utf8)
        guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: keyHandler.generateSecureKey()?.privateKey) else { return ""}
       return idToken
    }
    
    public func generateKeyId() async throws -> String {
        let service = DCAppAttestService.shared
        return try await withCheckedThrowingContinuation { continuation in
            service.generateKey { keyId, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let keyId = keyId {
                    continuation.resume(returning: keyId)
                } else {
                    continuation.resume(throwing: NSError(domain: "AppAttest", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key generation failed"]))
                }
            }
        }
    }
    
    /// Attest `keyId` against `hash`.
    ///
    /// A throttled App Attest service (`serverUnavailable`) is retried on the
    /// same key and the same hash, which is what Apple asks for and what keeps
    /// the device's risk metric intact. Everything else - `invalidKey` above
    /// all, meaning this key has already been attested - is thrown to the
    /// caller, whose catch mints and stores a replacement.
    func generateDeviceIntegrityToken(keyId: String, hash: Data) async throws -> String {
        if #available(iOS 14.0, *) {
            return try await AppAttestRetry.attestExistingKey(
                service: DCAppAttestService.shared,
                keyId: keyId,
                clientDataHash: hash
            )
        }
        let service = DCAppAttestService.shared
        return try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyId, clientDataHash: hash) { attestation, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let attestation = attestation {
                    continuation.resume(returning: attestation.base64EncodedString())
                } else {
                    continuation.resume(throwing: NSError(domain: "AppAttest", code: -1, userInfo: [NSLocalizedDescriptionKey: "Attestation failed"]))
                }
            }
        }
    }
    
    func processWalletUnitAttestationRequest(attestation: String, nonce: String, keyId: String, clientAssertion: String, profile: String? = nil) async -> WalletUnitAttestationResponse? {
        var credentialOfferUri: String = ""
        var response: WalletUnitAttestationResponse?
        let url = "\(baseURL)/wallet-unit/request"
        var request = URLRequest(url: URL(string: url)!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(attestation, forHTTPHeaderField: "X-Wallet-Unit-Integrity-Token")
        request.setValue("ios", forHTTPHeaderField: "X-Wallet-Unit-Platform")
        request.setValue(nonce, forHTTPHeaderField: "X-Wallet-Unit-Nonce")
        request.setValue(keyId, forHTTPHeaderField: "X-Wallet-Unit-KeyID")

        // ARF TS3 opt-in: profile:"ts3" asks the wallet provider for a TS3 WIA
        // (x5c identity + client_status); nil keeps the legacy EWC shape.
        var bodyDict: [String: Any] = ["client_assertion": clientAssertion, "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]
        if let profile = profile, !profile.isEmpty {
            bodyDict["profile"] = profile
        }
        let body = bodyDict.toString()
        request.httpBody = body?.data(using: .utf8)
        
        do {
            let (data, resp) = try await NetworkLogger.send(request, tag: "wallet-unit-attestation")
            let jsonObject = try JSONSerialization.jsonObject(with: data, options: [])
            let dictionary = jsonObject as? [String: Any]
            var credentialOffer = dictionary?["credentialOffer"] as? String
            var walletUnitAttestation = dictionary?["walletUnitAttestation"] as? String
            var credentialIssuer = dictionary?["credentialIssuer"] as? String
            credentialOfferUri = credentialOffer ?? ""
            response = WalletUnitAttestationResponse(credentialOffer: credentialOffer ?? "", walletUnitAttestation: walletUnitAttestation ?? "", credentialIssuer: credentialIssuer ?? "")
        } catch {
            print("Error")
        }
        return response
    }
    
    /// `clientId`, when given, is the PoP `iss`: the client_id the attestation was
    /// issued for (its `sub`). Otherwise the signing key's DID, as before.
    public func generateWUAProofOfPossession(keyHandler: SecureKeyProtocol, aud: String? = nil, clientId: String? = nil) async -> String {
        let secureData = keyHandler.generateSecureKey()
        var did = clientId ?? ""
        if did.isEmpty {
            did = await createDIDforWUA(keyHandler: keyHandler)
        }
        let header = ([
            "alg": "ES256",
            "typ": "oauth-client-attestation-pop+jwt",
        ] as [String: Any]).toString() ?? ""
        let now = Int(Date().timeIntervalSince1970)
        // Short-lived by design: the PoP is per request, and the authorization
        // server keeps a list of witnessed jti values for replay detection
        // (draft-ietf-oauth-attestation-based-client-auth 5.2, 12.1). 6 minutes,
        // matching Android.
        let exp = now + 360
        let jti = UUID().uuidString
        let payload = ([
            "aud": aud ?? baseURL,
            "exp": exp,
            "iss": did,
            "jti": "urn:uuid:\(jti)",
            "iat": now,
            "nbf": now
        ] as [String: Any]).toString() ?? ""
        
        let headerData = Data(header.utf8)
        guard let popToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.privateKey) else { return ""}
        return popToken
    }

    /// Decode a JWT segment (header or payload) into a dictionary.
    private static func decodeJwtSegment(_ part: Substring) -> [String: Any]? {
        var s = String(part)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        guard let data = Data(base64Encoded: s),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return obj
    }

    /// ARF TS3 WIA detection: the JOSE header carries an x5c chain AND the
    /// payload carries a client_status claim.
    public static func isTs3Wia(_ jwt: String) -> Bool {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else { return false }
        let hasX5c = decodeJwtSegment(parts[0])?["x5c"] != nil
        let hasClientStatus = decodeJwtSegment(parts[1])?["client_status"] != nil
        return hasX5c && hasClientStatus
    }

    /// The TS3 WIA maintenance expiry (client_status.exp, epoch seconds), or nil.
    public static func ts3ClientStatusExp(_ jwt: String) -> Int? {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2,
              let payload = decodeJwtSegment(parts[1]),
              let clientStatus = payload["client_status"] as? [String: Any] else { return nil }
        if let exp = clientStatus["exp"] as? Int { return exp }
        if let expD = clientStatus["exp"] as? Double { return Int(expD) }
        return nil
    }

    /// True when a TS3 WIA is inside its maintenance window and should be
    /// re-registered: now >= client_status.exp - margin (default 30 min).
    public static func needsTs3MaintenanceRefresh(_ jwt: String, marginSeconds: Int = 1800) -> Bool {
        guard isTs3Wia(jwt), let exp = ts3ClientStatusExp(jwt) else { return false }
        let now = Int(Date().timeIntervalSince1970)
        return now >= (exp - marginSeconds)
    }

}

public struct WalletUnitAttestationResponse {
    public let credentialOffer: String?
    public let walletUnitAttestation: String?
    public let credentialIssuer: String?
    /// Protocol 2: the revocation code of a new registration, given once. Show
    /// it to the user once; never store it in plain text and never log it.
    public let revocationCode: String?

    public init(credentialOffer: String?, walletUnitAttestation: String?, credentialIssuer: String?,
                revocationCode: String? = nil) {
        self.credentialOffer = credentialOffer
        self.walletUnitAttestation = walletUnitAttestation
        self.credentialIssuer = credentialIssuer
        self.revocationCode = revocationCode
    }
}

/// Runs wallet-unit requests one after the other: each assertion carries a
/// counter that must be higher than the last one the wallet provider accepted.
@available(iOS 14.0, *)
actor WalletUnitRequestQueue {
    static let shared = WalletUnitRequestQueue()
    private var tail: Task<Void, Never>?

    func run<T>(_ operation: @escaping () async throws -> T) async throws -> T {
        let previous = tail
        let task = Task { () async throws -> T in
            _ = await previous?.value
            return try await operation()
        }
        tail = Task { _ = try? await task.value }
        return try await task.value
    }
}
