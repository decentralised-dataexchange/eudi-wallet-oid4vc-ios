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

    /// Same lookups, given the request's full certificate chain — **leaf first**, as it appears in a
    /// JWS `x5c` header or a COSE `x5chain`. Supply this whenever the request carries more than the
    /// signing certificate: a trust list may register the CA or an intermediate rather than the leaf,
    /// and only a lookup that sees the whole chain can match such an entry.
    func isIssuerOrVerifierTrusted(url: String?, data: TrustServiceStatusList?, x5c: String?, x5cChain: [String]?, jwksURI: String?, completion: @escaping (Bool?) -> Void)

    /// See `isIssuerOrVerifierTrusted(url:data:x5c:x5cChain:jwksURI:completion:)`.
    func fetchTrustDetails(url: String?, data: TrustServiceStatusList?, x5c: String?, x5cChain: [String]?, jwksURI: String?, completion: @escaping (TrustServiceProvider?) -> Void)
}

/// A chain is only meaningful to an implementation that forwards it to a backend. The local/static
/// TSL implementation matches certificates one at a time, so it inherits these: the chain is
/// dropped and the leaf identifier is used, exactly as before.
extension TrustMechanismServiceProtocol {

    func isIssuerOrVerifierTrusted(url: String?, data: TrustServiceStatusList?, x5c: String?, x5cChain: [String]?, jwksURI: String?, completion: @escaping (Bool?) -> Void) {
        isIssuerOrVerifierTrusted(url: url, data: data, x5c: x5c ?? x5cChain?.first, jwksURI: jwksURI, completion: completion)
    }

    func fetchTrustDetails(url: String?, data: TrustServiceStatusList?, x5c: String?, x5cChain: [String]?, jwksURI: String?, completion: @escaping (TrustServiceProvider?) -> Void) {
        fetchTrustDetails(url: url, data: data, x5c: x5c ?? x5cChain?.first, jwksURI: jwksURI, completion: completion)
    }
}
