//
//  File.swift
//
//
//  Created by iGrant on 25/07/24.
//
import Foundation
protocol CredentialValidaorProtocol {
       func validateCredential(jwt: String?, jwksURI: String?, format: String) async throws
}
