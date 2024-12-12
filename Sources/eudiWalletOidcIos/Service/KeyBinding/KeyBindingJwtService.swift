//
//  File.swift
//
//
//  Created by josmilan on 10/12/24.
//
import Foundation
public class KeyBindingJwtService: KeyBindingJwtServiceProtocol {
    
    public init() {}
    // need to pass claims (transaction data hash and aud) other 3 claims are predefined and added here
    func generateKeyBindingJwt(issuerSignedJwt: String?, claims: [String: Any], keyId: String?) async -> String? {
        guard let issuerSignedData = issuerSignedJwt else { return nil }
        
        let header = ([
            "alg": "ES256",
            "typ": "kb+jwt"
        ] as [String: Any]).toString() ?? ""
        let nonce = UUID().uuidString
        let currentTime = Int(Date().timeIntervalSince1970)
        let iat = currentTime
        
        var predefinedClaims: [String: Any] = [
            "iat": iat,
            "nonce": nonce,
            "sd_hash": SDJWTService.shared.calculateSHA256Hash(inputString: issuerSignedJwt)
        ]
        
        predefinedClaims.merge(claims) { (_, new) in new }
        let headerData = Data(header.utf8)
        let keyHandler = SecureEnclaveHandler(organisationID: keyId ?? "")
        let secureData = await DidService.shared.createSecureEnclaveJWK(keyHandler: keyHandler)
        guard let jwt = keyHandler.sign(payload: predefinedClaims.toString() ?? "", header: headerData, withKey: secureData?.1.privateKey) else{return ""}
        
        return jwt
    }
}
