//
//  File.swift
//  
//
//  Created by Arun Raj on 27/06/24.
//

import Foundation

public struct SecureKeyData{
    public var publicKey: Data
    public var privateKey: Data?
    
    public init(publicKey: Data, privateKey: Data? = nil) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}

public protocol SecureKeyProtocol: NSObjectProtocol{
    func generateSecureKey() -> SecureKeyData?
    func sign(payload: String, header: Data, withKey privateKey: Data?) -> String?
   
}
