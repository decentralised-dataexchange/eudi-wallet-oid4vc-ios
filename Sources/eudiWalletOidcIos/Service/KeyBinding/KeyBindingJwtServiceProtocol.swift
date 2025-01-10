//
//  File.swift
//
//
//  Created by josmilan on 10/12/24.
//
import Foundation
protocol KeyBindingJwtServiceProtocol {
    
    func generateKeyBindingJwt(issuerSignedJwt: String?, claims: [String: Any], keyHandler: SecureKeyProtocol) async -> String?
    
}
