//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 11/06/25.
//

import Foundation

protocol TrustMechanismServiceProtocol {
    
    func isIssuerOrVerifierTrusted(url: String?, data: TrustServiceStatusList?, x5c: String?, jwksURI: String?, completion: @escaping (Bool?) -> Void)
    
    func fetchTrustDetails(url: String?, data: TrustServiceStatusList?, x5c: String?, jwksURI: String?, completion: @escaping (TrustServiceProvider?) -> Void)
}
