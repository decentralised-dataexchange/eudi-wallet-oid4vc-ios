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
    var organisationID = ""
    var secureEnclaveHandler: SecureEnclave?
    
    public init(organisationID: String) {
        super.init()
        self.organisationID = organisationID
    }
    
    private func createSecureEnclaveHandlerFor() -> Bool{
        if !organisationID.isEmpty{
            secureEnclaveHandler = nil
            privateKeyLabel = "com.EudiWallet.\(organisationID).PrivateKey"
            //publicKeyLabel = "com.EudiWallet.\(organisationID).PrivateKey"
            secureEnclaveHandler = SecureEnclave(privateKeyApplicationTag: privateKeyLabel)
            return true
            } else{
            // invalid organisation id
            return false
        }
    }
    
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
    
//    private func getSecureKeys() -> (public: SecureEnclaveKeyData, private: SecureEnclaveKeyReference)?{
//        do{
//            if let privateKey = try? secureEnclaveHandler?.getPrivateKey(){
//                if let publicKey = try? secureEnclaveHandler?.getPublicKey(){
//                    return (publicKey, privateKey)
//                }
//            }
//            return nil
//        }
//        catch{
//            print("Error retrieving the key")
//            return nil
//        }
//    }
    
    public func sign(payload: String, header: Data, withKey privateKey: Data?) -> String?{
        if createSecureEnclaveHandlerFor(){
            do{
                if let signedData = try secureEnclaveHandler?.sign(payload, header: header){
                    if ((try secureEnclaveHandler?.verify(signedData)) != nil){
                        print("verified")
                    }
                    return signedData
                }
            }
            catch{
                return nil
            }
        }
        return nil
    }
    
}
