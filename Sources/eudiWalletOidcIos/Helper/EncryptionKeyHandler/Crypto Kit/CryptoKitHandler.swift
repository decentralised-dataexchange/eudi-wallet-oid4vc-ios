//
//  File.swift
//  
//
//  Created by Arun Raj on 27/06/24.
//

import Foundation
import CryptoKit

public class CryptoKitHandler:NSObject, SecureKeyProtocol{
    
    public var keyStorageType: SecureKeyTypes = .cryptoKit
    
    public func generateSecureKey() -> SecureKeyData?{
        let privateKey =  P256.Signing.PrivateKey()
        return SecureKeyData(publicKey: privateKey.publicKey.rawRepresentation, privateKey: privateKey.rawRepresentation)
    }
    
    public func sign(payload: String, header: Data, withKey privateKey: Data?) -> String?{
        if let privateKeyData = privateKey{
            do{

                let payloadData = Data(payload.utf8)
                let unsignedToken = "\(header.base64URLEncodedString()).\(payloadData.base64URLEncodedString())"
                if let data = unsignedToken.data(using: .utf8){
                    let privateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKeyData)
                    let signedData = try privateKey.signature(for: data)
                    let idToken = "\(unsignedToken).\(signedData.rawRepresentation.base64URLEncodedString())"
                    return idToken
                }
            }
            catch{
                return nil
            }
        }
        return nil
    }
    
}
