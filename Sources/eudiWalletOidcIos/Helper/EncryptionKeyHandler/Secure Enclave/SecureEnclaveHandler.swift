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
    
    //Creating secure enclave instance with unique identifer for the keys
    private func createSecureEnclaveHandlerFor() -> Bool{
        if !keyID.isEmpty{
            secureEnclaveHandler = nil
            privateKeyLabel = "com.EudiWallet.\(keyID).PrivateKey"
            secureEnclaveHandler = SecureEnclave(privateKeyApplicationTag: privateKeyLabel)
            return true
            } else{
            // invalid organisation id
            return false
        }
    }
    
    //Generate private and public keys from secure enclave and pass the public key back
    //private key is stored securely within secure enclave is not accessible directly
    public func generateSecureKey() -> SecureKeyData?{
        if createSecureEnclaveHandlerFor(){
            do{
                let anyExistingKey = try SecureEnclave.loadKeyPair(with: privateKeyLabel)
                
                if let publicKeyData = convertSecKeyToData(key: anyExistingKey.publicKey){
                    return SecureKeyData(publicKey: publicKeyData, privateKey: nil)
                }
            }
            catch{
                
                do{
                    let newKeys = try SecureEnclave.generateKeyPair(with: privateKeyLabel)
                    if let publicKeyData = convertSecKeyToData(key: newKeys.publicKey){
                        return SecureKeyData(publicKey: publicKeyData, privateKey: nil)
                    }
                }
                catch{
                    print("Error retrieving the key")
                    return nil
                }
                
            }
            
        }
        return nil
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
    
}
