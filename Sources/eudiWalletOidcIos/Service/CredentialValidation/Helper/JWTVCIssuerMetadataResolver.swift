//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 09/01/26.
//

import Foundation
import AnyCodable

public class JWTVCIssuerMetadataResolver {
    public init() {}
    
    func validateIssuerURL(_ iss: String) -> URL? {
        guard let url = URL(string: iss),
              url.scheme == "https",
              url.host != nil,
              url.query == nil,
              url.fragment == nil
        else {
            return nil
        }
        return url
    }
    
    func buildIssuerMetadataURL(from issURL: URL) -> URL? {
        var components = URLComponents(url: issURL, resolvingAgainstBaseURL: false)
        let path = issURL.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        
        if path.isEmpty {
            components?.path = "/.well-known/jwt-vc-issuer"
        } else {
            components?.path = "/.well-known/jwt-vc-issuer/\(path)"
        }
        
        return components?.url
    }
    
    func fetchIssuerMetadata(from url: URL) async throws -> JwtVcIssuerMetadata {
        let (data, _) = try await URLSession.shared.data(from: url)
        return try JSONDecoder().decode(JwtVcIssuerMetadata.self, from: data)
    }
    
    func resolveJWKs(
        metadata: JwtVcIssuerMetadata,
        kid: String?
    ) async -> [Any] {
        var jwksArray: [Any] = []
        // JWKS
        if let keys = metadata.jwks?.keys {
            for key in keys {
                let dict = key.toAnyDictionary()
                if kid == nil || dict["kid"] as? String == kid {
                    jwksArray.append(dict)
                }
            }
        }
        // JWKS URI
        if let jwksURI = metadata.jwks_uri {
            let jwk = await ProcessJWKFromJwksUri
                .processJWKFromJwksURI2(kid: kid, jwksURI: jwksURI)
            if !jwk.isEmpty {
                jwksArray.append(jwk)
            }
        }
        
        return jwksArray
    }
    
}

struct JwtVcIssuerMetadata: Decodable {
    let issuer: String
    let jwks: JWKSet?
    let jwks_uri: String?
}

struct JWKSet: Decodable {
    let keys: [[String: AnyCodable]]
}
