//
//  CodeVerifierService.swift
//
//
//  Created by Mumthasir mohammed on 13/03/24.
//

import Foundation
import CryptoKit

public class CodeVerifierService: CodeVerifierProtocol {
    
    static var shared = CodeVerifierService()
    private init(){}
    
    // Generates a code challenge string for PKCE (Proof Key for Code Exchange) based on the provided code verifier.
    /// - Parameter codeVerifier: The code verifier string used to generate the code challenge.
    /// - Returns: A code challenge string if successful; otherwise, nil.
    public func generateCodeChallenge(codeVerifier: String) -> String? {
        if let verifierData = codeVerifier.data(using: .utf8) {
            let digest = calculateSHA256Digest(for: verifierData)
            let base64URLSafe = digest.urlSafeBase64EncodedString()
            debugPrint("Code Verifier: \(codeVerifier)")
            debugPrint("SHA256 Digest: \(digest.toHexString())")
            debugPrint("Base64 URL Safe: \(base64URLSafe)")
            return base64URLSafe
        } else {
            debugPrint("Failed to generate code verifier.")
            return nil
        }
    }
    
    // Generates a random code verifier string for PKCE (Proof Key for Code Exchange).
    /// - Returns: A randomly generated code verifier string.
    public func generateCodeVerifier() -> String? {
        let characterSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        let verifierLength = Int.random(in: 44..<128) // Length greater than 43 and less than 128
        
        let verifier = String((0..<verifierLength).map { _ in
            characterSet.randomElement()!
        })
        
        return verifier
    }
    
    // Calculates the SHA-256 digest for the given input data.
    /// - Parameter input: The input data for which the SHA-256 digest is to be calculated.
    /// - Returns: The SHA-256 digest data.
    private func calculateSHA256Digest(for input: Data) -> Data {
        let digest = SHA256.hash(data: input)
        return Data(digest)
    }
}
