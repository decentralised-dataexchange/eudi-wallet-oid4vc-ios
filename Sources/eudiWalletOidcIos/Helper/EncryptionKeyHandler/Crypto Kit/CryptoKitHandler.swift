//
//  File.swift
//  
//
//  Created by Arun Raj on 27/06/24.
//

import Foundation
import CryptoKit

public class CryptoKitHandler:NSObject, SecureKeyProtocol{
    
    public func generateSecureKey() -> SecureKeyData?{
        let privateKey =  P256.Signing.PrivateKey()
        return SecureKeyData(publicKey: privateKey.publicKey.rawRepresentation, privateKey: privateKey.rawRepresentation)
    }
    
    public func sign(data: Data, withKey privateKey: Data?) -> Data?{
        if let privateKeyData = privateKey{
            do{
                let privateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKeyData)
                let signedData = try privateKey.signature(for: data)
                return signedData.rawRepresentation
            }
            catch{
                return nil
            }
        }
        return nil
    }
    
}
