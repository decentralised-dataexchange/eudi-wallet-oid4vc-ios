//
//  DidService.swift
//
//
//  Created by Mumthasir mohammed on 06/03/24.
//

import Foundation
import CryptoKit
import Base58Swift

public class DidService {
    public static var shared = DidService()
    private init(){}
    
    // MARK: - Creates a Decentralized Identifier (DID) asynchronously based on the provided JWK (JSON Web Key).
    ///
    /// - Parameter jwk: The JSON Web Key (JWK) used to create the DID.
    /// - Returns: The created DID string, or nil if an error occurs.
    public func createDID(jwk: [String: Any], cryptographicAlgorithm: String? = CryptographicAlgorithms.ES256.rawValue) async -> String? {
        switch cryptographicAlgorithm {
        case CryptographicAlgorithms.ES256.rawValue:
            return await createES256DID(jwk: jwk)
        case CryptographicAlgorithms.EdDSA.rawValue:
            return await createEdDSADID(jwk: jwk)
        default:
            return await createES256DID(jwk: jwk)
        }
        
    }
    
    public func createES256DID(jwk: [String: Any]) async -> String? {
        do {
            // Step 1: Convert JWK to JSON string
            let jsonData = try JSONSerialization.data(withJSONObject: jwk, options: [.sortedKeys])
            guard let jsonString = String(data: jsonData, encoding: .utf8) else {
                return nil
            }
            
            // Step 2: Remove whitespaces from the JSON string
            let compactJsonString = jsonString.replacingOccurrences(of: " ", with: "")
            
            // Step 3: UTF-8 encode the string
            guard let encodedData = compactJsonString.data(using: .utf8) else {
                return nil
            }
            
            // Step 4: Add multicodec byte for jwk_jcs-pub
            let multicodecByte: [UInt8] = [209, 214, 3]
            var multicodecData = Data(fromArray: multicodecByte)
            multicodecData.append(encodedData)
            
            // Step 5: Apply multibase base58-btc encoding
            let multibaseEncodedString =  Base58.base58Encode([UInt8](multicodecData))
            
            // Step 6: Prefix the string with did:key:z
            let didKeyIdentifier = "did:key:z" + multibaseEncodedString
            
            return didKeyIdentifier
        } catch {
            print("Error: \(error)")
            return nil
        }
    }
    
    public func createEdDSADID(jwk: [String: Any]) async -> String? {
        do {
            let decodedBytes = Base58.base58Decode(jwk["x"] as? String ?? "")
            // unicode to utf8 "\xed\x01" = [5c 78 65 64 5c 78 30 31]
            let multicodeByreArray: [UInt8] = [237, 1]
            var hexWithMulticode = multicodeByreArray
            hexWithMulticode.append(contentsOf: decodedBytes ?? [])
            let encodedString = Base58.base58Encode(hexWithMulticode)
            let finalString = "z" + encodedString
            return "did:key:" + finalString
        } catch {
            print("Error: \(error)")
            return nil
        }
    }
    
    // MARK: - Exposed method to create a JSON Web Key (JWK) asynchronously.
    /// - Parameter keyHandler: A handler to encryption key generation class
    /// - Returns: A dictionary representing the JWK, or nil if an error occurs.
    public func createJWK(keyHandler: SecureKeyProtocol) async -> ([String: Any], SecureKeyData)?{
        switch keyHandler.keyStorageType {
        case .cryptoKit:
            return await createES256JWK(keyHandler: keyHandler)
        case .eddsa:
            return await createEdDSAJWK(keyHandler: keyHandler)
        default:
            return await createSecureEnclaveJWK(keyHandler: keyHandler)
        }
    }
    
    public func createES256JWK(keyHandler: SecureKeyProtocol) async -> ([String: Any], SecureKeyData)?{
        if let keys = keyHandler.generateSecureKey(){
            let rawRepresentation = keys.publicKey
            let x = rawRepresentation[rawRepresentation.startIndex..<rawRepresentation.index(rawRepresentation.startIndex, offsetBy: 32)]
            let y = rawRepresentation[rawRepresentation.index(rawRepresentation.startIndex, offsetBy: 32)..<rawRepresentation.endIndex]
            let jwk: [String: Any] = [
                "crv": "P-256",
                "kty": "EC",
                "x": x.urlSafeBase64EncodedString(),
                "y": y.urlSafeBase64EncodedString()
            ]
            if let theJSONData = try? JSONSerialization.data(
                withJSONObject: jwk,
                options: []) {
                let theJSONText = String(data: theJSONData,
                                         encoding: .ascii)
                print("JSON string = \(theJSONText!)")
            }
            return (jwk, SecureKeyData(publicKey: keys.publicKey, privateKey: keys.privateKey))
        }
        return nil
    }
    
    public func createEdDSAJWK(keyHandler: SecureKeyProtocol) async -> ([String: Any], SecureKeyData)?{
        if let keys = keyHandler.generateSecureKey(){
            let rawRepresentation = keys.publicKey
            let jwk: [String: Any] = [
                "kty": "OKP",
                "crv": "Ed25519",
                "x": rawRepresentation.urlSafeBase64EncodedString()
            ]

            if let theJSONData = try? JSONSerialization.data(
                withJSONObject: jwk,
                options: []) {
                let theJSONText = String(data: theJSONData,
                                         encoding: .ascii)
                print("JSON string = \(theJSONText!)")
            }
            return (jwk, SecureKeyData(publicKey: keys.publicKey, privateKey: keys.privateKey))
        }
        return nil
    }
    
    public func createSecureEnclaveJWK(keyHandler: SecureKeyProtocol) async -> ([String: Any], SecureKeyData)?{
        if let keys = keyHandler.generateSecureKey(){
            if let jsonDict = keyHandler.getJWK(publicKey: keys.publicKey){
                return (jsonDict, SecureKeyData(publicKey: keys.publicKey, privateKey: keys.privateKey))
            }
        }
        return nil
    }
}
