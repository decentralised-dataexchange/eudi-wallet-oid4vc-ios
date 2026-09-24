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
    public func initiateWalletUnitAttestation(walletProviderUrl: String, profile: String? = nil, keyHandler inputKeyHandler: SecureKeyProtocol? = nil) async throws -> (String, WalletUnitAttestationResponse?){
            baseURL = walletProviderUrl
            let service = DCAppAttestService.shared
            let inputString = await fetchNonceForDeviceIntegrityToken(nonceEndPoint:  "\(baseURL)/nonce")
            let inputData = Data(inputString.utf8)
            let hash = Data(SHA256.hash(data: inputData))
            var keyId: String = ""
            let keyIDfromKeyChain = retrieveKeyIdFromKeychain()
            if keyIDfromKeyChain == "" || keyIDfromKeyChain == nil {
                keyId = try await generateKeyId()
                storeKeyIdInKeychain(keyId)
            } else {
                keyId = keyIDfromKeyChain ?? ""
            }
            
        var keyHandler: SecureKeyProtocol = inputKeyHandler ?? SecureEnclaveHandler(keyID: keyId)
            do {
                let attest = try await generateDeviceIntegrityToken(keyId: keyId, hash: hash)
                let clientAssertion = await createClientAssertion(keyHandler: keyHandler)
                let credentialOffer = await processWalletUnitAttestationRequest(
                    attestation: attest,
                    nonce: inputString,
                    keyId: keyId,
                    clientAssertion: clientAssertion,
                    profile: profile
                )
                return (clientAssertion, credentialOffer)
            } catch {
                print("Error during attestation with keyId: \(keyId), regenerating key ID...")
                keyId = try await generateKeyId()
                storeKeyIdInKeychain(keyId) // Update Keychain with the new key ID
                keyHandler = inputKeyHandler ?? SecureEnclaveHandler(keyID: keyId)
                // Retry the attestation process
                let attestRetry = try await generateDeviceIntegrityToken(keyId: keyId, hash: hash)
                let clientAssertionRetry = await createClientAssertion(keyHandler: keyHandler)
                let credentialOfferRetry = await processWalletUnitAttestationRequest(
                    attestation: attestRetry,
                    nonce: inputString,
                    keyId: keyId,
                    clientAssertion: clientAssertionRetry,
                    profile: profile
                )
                return (clientAssertionRetry, credentialOfferRetry)
            }
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
    
    private func fetchNonceForDeviceIntegrityToken(nonceEndPoint: String) async -> String {
        if let nonce = await NonceService().fetchNonceEndpoint(nonceEndPoint: nonceEndPoint) {
            return nonce
        } else {
            return ""
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
            let responseData =  String(data: data, encoding: .utf8)
            let jsonObject = try JSONSerialization.jsonObject(with: data, options: [])
            let dictionary = jsonObject as? [String: Any]
            var credentialOffer = dictionary?["credentialOffer"] as? String
            var walletUnitAttestation = dictionary?["walletUnitAttestation"] as? String
            var credentialIssuer = dictionary?["credentialIssuer"] as? String
            credentialOfferUri = credentialOffer ?? ""
            response = WalletUnitAttestationResponse(credentialOffer: credentialOffer ?? "", walletUnitAttestation: walletUnitAttestation ?? "", credentialIssuer: credentialIssuer ?? "")
            print("data: \(responseData)")
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

    public init(credentialOffer: String?, walletUnitAttestation: String?, credentialIssuer: String?) {
        self.credentialOffer = credentialOffer
        self.walletUnitAttestation = walletUnitAttestation
        self.credentialIssuer = credentialIssuer
    }
}
