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
    var secureEnclaveHandler: SecureEnclaveHelper?
    
    public init(organisationID: String) {
        super.init()
        self.organisationID = organisationID
    }
    
    private func createSecureEnclaveHandlerFor() -> Bool{
        if !organisationID.isEmpty{
            secureEnclaveHandler = nil
            privateKeyLabel = "com.EudiWallet.\(organisationID).PrivateKey"
            publicKeyLabel = "com.EudiWallet.\(organisationID).PrivateKey"
            secureEnclaveHandler = SecureEnclaveHelper(publicLabel: publicKeyLabel, privateLabel: privateKeyLabel, operationPrompt: "Require authorisation to continue")
            return true
            } else{
            // invalid organisation id
            return false
        }
    }
    
    public func generateSecureKey() -> SecureKeyData?{
        if createSecureEnclaveHandlerFor(){
            if getSecureKeys() == nil{
                do{
                    if let accessControl = try secureEnclaveHandler?.accessControl(){
                        let keys = try secureEnclaveHandler?.generateKeyPair(accessControl: accessControl)
                        if let retrievedKeys = getSecureKeys(){
                            return SecureKeyData(publicKey: retrievedKeys.public.data, privateKey: nil)
                        }
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
    
    private func getSecureKeys() -> (public: SecureEnclaveKeyData, private: SecureEnclaveKeyReference)?{
        do{
            if let privateKey = try secureEnclaveHandler?.getPrivateKey(){
                if let publicKey = try secureEnclaveHandler?.getPublicKey(){
                    return (publicKey, privateKey)
                }
            }
            return nil
        }
        catch{
            print("Error retrieving the key")
            return nil
        }
    }
    
    public func sign(data: Data, withKey privateKey: Data?) -> Data?{
        if createSecureEnclaveHandlerFor(){
            do{
                if let privateKey = try secureEnclaveHandler?.getPrivateKey(){
                    let signedData = try secureEnclaveHandler?.sign(data, privateKey: privateKey)
                    return signedData
                }
            }
            catch{
                return nil
            }
        }
        return nil
    }
    
    public func isPrivateKeyStoredInternally() -> Bool {
        return true
    }
}
