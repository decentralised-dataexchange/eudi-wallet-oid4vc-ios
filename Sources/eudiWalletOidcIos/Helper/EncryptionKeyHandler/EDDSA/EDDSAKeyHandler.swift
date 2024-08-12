//
//  File.swift
//
//
//  Created by Milan on 25/07/24.
//

import Foundation
import Crypto

public class EDDSAKeyHandler:NSObject, SecureKeyProtocol{
    
    public var keyStorageType: SecureKeyTypes = .eddsa
    
    public func generateSecureKey() -> SecureKeyData?{
        let privateKey = Curve25519.Signing.PrivateKey()
        return SecureKeyData(publicKey: privateKey.publicKey.rawRepresentation, privateKey: privateKey.rawRepresentation)
    }
    

    public func sign(payload: String, header: Data, withKey privateKey: Data?) -> String?{
        if let privateKeyData = privateKey{
            do{

                let payloadData = Data(payload.utf8)
                let unsignedToken = "\(header.base64URLEncodedString()).\(payloadData.base64URLEncodedString())"
                if let data = unsignedToken.data(using: .utf8){
                    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
                    let signedData = try privateKey.signature(for: data)
                    let idToken = "\(unsignedToken).\(signedData.urlSafeBase64EncodedString()))"
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
