//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 08/01/26.
//

import Foundation

public class JWKResolver {
    public init(){}
    
    public func resolve(
        kid: String?,
        x5cChain: [String]?
    ) async throws -> [Any] {
        var jwk: [String: Any] = [:]
        var jwksArray: [Any] = []
        
        if let x5cChain, !x5cChain.isEmpty {
            jwksArray.append(x5cChain)
        }
        
        if let kid = kid {
            if kid.hasPrefix("did:jwk:") {
                if let parsedJWK = ProcessJWKFromKID.parseDIDJWK(kid) {
                    jwksArray.append(parsedJWK)
                }
            }
            if kid.hasPrefix("did:key:z") {
                jwk = ProcessKeyJWKFromKID.processJWKfromKid(did: kid)
                jwksArray.append(jwk)
            }
            if kid.hasPrefix("did:ebsi:z") {
                jwk = await ProcessEbsiJWKFromKID.processJWKforEBSI(kid: kid)
                jwksArray.append(jwk)
            }
            if kid.hasPrefix("did:web:") {
                if let publicKeyJwk = try? await ProcessWebJWKFromKID.fetchDIDDocument(did: kid){
                    jwk = publicKeyJwk
                    jwksArray.append(jwk)
                }
            }
            if kid.hasPrefix("did:tdw:") {
                if let publicKeyJwk = try await ProcessTrustWebJwkFromKid.fetchDIDDocument(did: kid) {
                    jwksArray.append(publicKeyJwk)
                }
            }
            if kid.hasPrefix("did:webvh:") {
                if let publicKeyJwk = try await ProcessWebVhFromKID.fetchDIDDocument(did: kid) {
                    jwksArray.append(publicKeyJwk)
                }
            }
            
        }
        return jwksArray
    }
}
