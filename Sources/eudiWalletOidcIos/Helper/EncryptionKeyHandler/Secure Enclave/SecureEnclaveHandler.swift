//
//  File.swift
//  
//
//  Created by Arun Raj on 27/06/24.
//

import Foundation

public class SecureEnclaveHandler: NSObject, SecureKeyProtocol{
    
    var privateKeyLabel = ""
    var publicKeyLabel = ""
    var keyID = ""
    var secureEnclaveHandler: SecureEnclave?
    public var keyStorageType: SecureKeyTypes = .cryptoKit
    
    public init(keyID: String) {
        super.init()
        self.keyID = keyID
        self.keyStorageType = .secureEnclave
    }
    
    /// Resolve the enclave key for this handler, once.
    ///
    /// This used to discard and rebuild on every call, so each operation ran
    /// its own Keychain lookup. That matters because the lookup is not exact:
    /// kSecAttrApplicationTag is passed as a String where the Security
    /// framework wants Data, so the tag does not reliably constrain the query
    /// and SecItemCopyMatching can answer with a different Secure Enclave key
    /// each time. Reporting a public key and then signing became two separate
    /// questions that could get two different answers.
    private func createSecureEnclaveHandlerFor() -> Bool{
        guard !keyID.isEmpty else {
            // invalid organisation id
            return false
        }
        let label = "com.EudiWallet.\(keyID).PrivateKey"
        if secureEnclaveHandler != nil, privateKeyLabel == label {
            return true
        }
        privateKeyLabel = label
        secureEnclaveHandler = SecureEnclave(privateKeyApplicationTag: label)
        return true
    }
    
    //Generate private and public keys from secure enclave and pass the public key back
    //private key is stored securely within secure enclave is not accessible directly
    public func generateSecureKey() -> SecureKeyData?{
        // Read the public key off the SAME key pair sign() uses, rather than
        // asking the Keychain again. Any divergence here shows up as a proof
        // whose header names one key and whose signature is made by another.
        guard createSecureEnclaveHandlerFor(),
              let keyPair = secureEnclaveHandler?.keyPair,
              let publicKeyData = convertSecKeyToData(key: keyPair.publicKey) else {
            return nil
        }
        return SecureKeyData(publicKey: publicKeyData, privateKey: nil)
    }
    
    func convertSecKeyToData(key: SecKey) -> Data?{
        var error: Unmanaged<CFError>?
        guard let publicKeydata = SecKeyCopyExternalRepresentation(key, &error) as? Data else {
            return nil
        }
        return publicKeydata
    }
    
    public func sign(payload: String, header: Data, withKey privateKey: Data?) -> String?{
        if createSecureEnclaveHandlerFor(){
            do{
                if let signedData = try secureEnclaveHandler?.sign(payload, header: header){
                    
                    return signedData
                }
            }
            catch{
                return nil
            }
        }
        return nil
    }
    
    public func getJWK(publicKey: Data) -> [String:Any]?{
        let jwk = secureEnclaveHandler?.getJWK(publicKey: publicKey)
        return jwk
    }
    
    public func getSecurePrivateKey() -> SecKey? {
        let privateKey = secureEnclaveHandler?.keyPair.privateKey
        return privateKey
    }
    
}
