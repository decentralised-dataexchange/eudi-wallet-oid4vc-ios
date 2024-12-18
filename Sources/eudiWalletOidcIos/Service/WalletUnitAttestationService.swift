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
    let baseURL = "https://oid4vc.igrant.io/organisation/445f2b74-cc27-44ef-bed7-4809c13699cf/service"
    
    public func initiateWalletUnitAttestation() async throws -> (String, String){
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
            do {
                let attest = try await generateDeviceIntegrityToken(keyId: keyId, hash: hash)
                let clientAssertion = await createClientAssertion(keyId: keyId)
                let credentialOffer = await processWalletUnitAttestationRequest(
                    attestation: attest,
                    nonce: inputString,
                    keyId: keyId,
                    clientAssertion: clientAssertion
                )
                return (clientAssertion, credentialOffer)
            } catch {
                print("Error during attestation with keyId: \(keyId), regenerating key ID...")
                keyId = try await generateKeyId()
                storeKeyIdInKeychain(keyId) // Update Keychain with the new key ID
                
                // Retry the attestation process
                let attestRetry = try await generateDeviceIntegrityToken(keyId: keyId, hash: hash)
                let clientAssertionRetry = await createClientAssertion(keyId: keyId)
                let credentialOfferRetry = await processWalletUnitAttestationRequest(
                    attestation: attestRetry,
                    nonce: inputString,
                    keyId: keyId,
                    clientAssertion: clientAssertionRetry
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
    
    // this will be modified once api avaliable
    func fetchNonceForDeviceIntegrityToken(nonceEndPoint: String) async -> String {
        var nonce: String = ""
        var request = URLRequest(url: URL(string: nonceEndPoint)!)
        request.httpMethod = "GET"
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let stringData = String.init(data: data, encoding: .utf8)
            let jsonObject = try JSONSerialization.jsonObject(with: data, options: [])
            let dict = jsonObject as? [String: Any]
            nonce = dict?["nonce"] as? String ?? ""
        } catch {
            print("error")
        }
        return nonce
    }
    
    public func createDIDforWUA(keyId: String) async -> String {
        let keyHandler = SecureEnclaveHandler(organisationID: keyId)
        let secureData = await DidService.shared.createSecureEnclaveJWK(keyHandler: keyHandler)
        let jwk = secureData?.0 ?? [:]
        let did = await DidService.shared.createDID(jwk: jwk) ?? ""
        return did
    }
    
    public func createClientAssertion(keyId: String, aud: String = "") async -> String {
        let keyHandler = SecureEnclaveHandler(organisationID: keyId)
        let secureData = await DidService.shared.createSecureEnclaveJWK(keyHandler: keyHandler)
        let jwk = secureData?.0 ?? [:]
        let did = await DidService.shared.createDID(jwk: jwk) ?? ""
        print("")
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
            "client_id": did,
            "cnf": ["jwk": jwk],
            "exp": exp,
            "iat": now,
            "iss": did,
            "jti": "urn:uuid:\(jti)",
            "sub": did
        ] as [String: Any]).toString() ?? ""
        let headerData = Data(header.utf8)
        guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.1.privateKey) else { return ""}
       return idToken
    }
    
    func generateKeyId() async throws -> String {
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
    
    func generateDeviceIntegrityToken(keyId: String, hash: Data) async throws -> String {
        let service = DCAppAttestService.shared
        return try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyId, clientDataHash: hash) { attestation, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let attestation = attestation {
                    let attestationData = attestation.base64EncodedString()
                    print("Attestation Data: \(attestation.base64URLEncodedString())")
                    continuation.resume(returning: attestationData)
                } else {
                    continuation.resume(throwing: NSError(domain: "AppAttest", code: -1, userInfo: [NSLocalizedDescriptionKey: "Attestation failed"]))
                }
            }
        }
    }
    
    func processWalletUnitAttestationRequest(attestation: String, nonce: String, keyId: String, clientAssertion: String) async -> String {
        var credentialOfferUri: String = ""
        let url = "\(baseURL)/wallet-unit/request"
        var request = URLRequest(url: URL(string: url)!)
        request.httpMethod = "POST"
        request.setValue(attestation, forHTTPHeaderField: "X-Wallet-Unit-Integrity-Token")
        request.setValue("ios", forHTTPHeaderField: "X-Wallet-Unit-Platform")
        request.setValue(nonce, forHTTPHeaderField: "X-Wallet-Unit-Nonce")
        request.setValue(keyId, forHTTPHeaderField: "X-Wallet-Unit-KeyID")
        
        let body = ["client_assertion": clientAssertion, "client_assertion_type" : "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"].toString()
        request.httpBody = body?.data(using: .utf8)
        
        do {
            let (data, resp) = try await URLSession.shared.data(for: request)
            let responseData =  String(data: data, encoding: .utf8)
            let jsonObject = try JSONSerialization.jsonObject(with: data, options: [])
            let dictionary = jsonObject as? [String: Any]
            var credentialOffer = dictionary?["credentialOffer"] as? String
            credentialOfferUri = credentialOffer ?? ""
            print("data: \(responseData)")
        } catch {
            print("Error")
        }
        return credentialOfferUri
    }
    
    public func generateWUAProofOfPossession(keyId: String, aud: String? = nil) async -> String {
        let keyHandler = SecureEnclaveHandler(organisationID: keyId)
        let secureData = await DidService.shared.createSecureEnclaveJWK(keyHandler: keyHandler)
        let keyId = retrieveKeyIdFromKeychain()
        let did = await createDIDforWUA(keyId: keyId ?? "")
        let header = ([
            "alg": "ES256",
        ] as [String: Any]).toString() ?? ""
        let now = Int(Date().timeIntervalSince1970)
        let exp = now + 3600
        let jti = UUID().uuidString
        let payload = ([
            "aud": aud ?? baseURL,
            "exp": exp,
            "iss": did,
            "jti": "urn:uuid:\(jti)",
            "nbf": now
        ] as [String: Any]).toString() ?? ""
        
        let headerData = Data(header.utf8)
        guard let popToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.1.privateKey) else { return ""}
        return popToken
    }
    
}
