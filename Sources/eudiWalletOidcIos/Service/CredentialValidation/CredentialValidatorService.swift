//
//  File.swift
//
//
//  Created by iGrant on 24/07/24.
//

import Foundation
import Base58Swift

public enum ValidationError: Error {
    case JWTExpired
    case signatureExpired
}

public class CredentialValidatorService: CredentialValidaorProtocol {
    public static var shared = CredentialValidatorService()
    public init() {}
    
    public func validateCredential(jwt: String?, jwksURI: String?) async throws {
        let isJWTExpired = ExpiryValidator.validateExpiryDate(jwt: jwt) ?? false
        let isSignatureExpied = await SignatureValidator.validateSign(jwt: jwt, jwksURI: jwksURI) ?? false
        if isJWTExpired {
            throw ValidationError.JWTExpired
        }
        if !isSignatureExpied {
            throw ValidationError.signatureExpired
        }
    }
    
}
