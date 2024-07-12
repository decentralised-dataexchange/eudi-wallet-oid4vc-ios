//
//  SecureKeyProtocol.swift
//  A protocol class to be implemented by the encrytion key generation classes
//  to provide standardised api to apps
//  Created by Arun Raj on 27/06/24.
//

import Foundation

//Enum to identify the type of key generation class used like CryptoKitHandler, SecureEnclaveHandler
public enum SecureKeyTypes{
    case cryptoKit
    case secureEnclave
}

public struct SecureKeyData{
    public var publicKey: Data
    public var privateKey: Data?
    
    public init(publicKey: Data, privateKey: Data? = nil) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}

public protocol SecureKeyProtocol: NSObjectProtocol{
    var keyStorageType: SecureKeyTypes { get set } //value for storing the key generation type used
    func generateSecureKey() -> SecureKeyData? //for generating new private & public keys
    func sign(payload: String, header: Data, withKey privateKey: Data?) -> String? //sign data
    func getJWK(publicKey:Data) -> [String:Any]? //get the json web key for did generation
}

extension SecureKeyProtocol{
    public func getJWK(publicKey:Data) -> [String:Any]? {return nil}
}
