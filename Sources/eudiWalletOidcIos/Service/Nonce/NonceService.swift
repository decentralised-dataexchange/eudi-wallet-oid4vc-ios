//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 06/06/25.
//

import Foundation

public class NonceService: NonceServiceProtocol {
    
    public static var shared = NonceService()
    public init() {}
    
    /// - Parameter urlSession: injected so the endpoint can be stubbed in tests. It defaulted to
    ///   `URLSession.shared` inside `NetworkLogger`, which meant this call could not be stubbed at
    ///   all -- the same trap the token tests were written to escape. Callers that do not pass one
    ///   behave exactly as before.
    public func fetchNonceEndpoint(
        accessToken: String? = nil,
        nonceEndPoint: String?,
        urlSession: URLSession = .shared
    ) async -> String? {
        guard let url = URL(string: nonceEndPoint ?? "") else { return nil }
        
        var request = URLRequest(url: url)
        // OpenID4VCI 1.0 nonce endpoint is unauthenticated. A Bearer copy of a
        // DPoP-bound access token makes strict issuers answer 401,
        // and the flow then loses its c_nonce — so no Authorization header is sent.
        _ = accessToken
        request.httpMethod = "POST"
        
        do {
            let (data, response) = try await NetworkLogger.send(request, tag: "nonce", session: urlSession)
            let httpRes = response as? HTTPURLResponse
            if httpRes?.statusCode ?? 0 >= 400 {
                return nil
            }
            else {
        guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else { return nil }
        
                
                return jsonObject["c_nonce"] as? String
            }
        } catch {
            return nil
        }
    }
    
}
