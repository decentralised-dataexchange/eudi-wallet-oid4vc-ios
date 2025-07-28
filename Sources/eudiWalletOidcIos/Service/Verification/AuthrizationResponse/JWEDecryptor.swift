//
//  File.swift
//  eudi-wallet-oid4vc-ios
//
//  Created by iGrant on 28/07/25.
//

import Foundation
import CryptoKit
import JOSESwift

class JWEDecryptor {
    
    func decrypt(_ jweString: String, privateKey: ECPrivateKey?) -> String? {
        guard let privateKey = privateKey else { return nil }
        
        do {
            let jwe = try JWE(compactSerialization: jweString)
            
            guard let decrypter = try Decrypter(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A128CBCHS256, decryptionKey: privateKey) else { return nil}
            
            
            let decryptedData = try jwe.decrypt(using: decrypter)
            return String(data: decryptedData.data(), encoding: .utf8)
            
        } catch {
            print("Decryption failed: \(error)")
            return nil
        }
    }
    
}
