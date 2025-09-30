//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 29/09/25.
//

import Foundation
import JOSESwift

public class ReissueService {
    public init() {}
    
    public func reissueCredential(
        did: String,
        nonce: String,
        credentialOffer: CredentialOffer,
        issuerConfig: IssuerWellKnownConfiguration,
        accessToken: String,
        format: String,
        credentialTypes: [String], tokenResponse: TokenResponse? = nil, authDetails: AuthorizationDetails? = nil, privateKey: ECPrivateKey?, keyHandler: SecureEnclaveHandler) async -> CredentialResponse? {
            
            let jsonDecoder = JSONDecoder()
            guard let url = URL(string: issuerConfig.credentialEndpoint ?? "") else { return nil }
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue( "Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
            
            guard let idToken = await ProofService.generateProof(nonce: nonce, credentialOffer: credentialOffer, issuerConfig: issuerConfig, did: did, keyHandler: keyHandler) else {return nil}
            let issueHandler = IssueService(keyHandler: keyHandler)
            //let credentialTypes = getTypesFromCredentialOffer(credentialOffer: credentialOffer) ?? []
            let types = issueHandler.getTypesFromIssuerConfig(issuerConfig: issuerConfig, type: credentialTypes.last ?? "")
            let formatT = issueHandler.getFormatFromIssuerConfig(issuerConfig: issuerConfig, type: credentialTypes.last)
            let doctType = issueHandler.getDocTypeFromIssuerConfig(issuerConfig: issuerConfig, type: credentialTypes.last)
            var params: [String: Any] = [:]
            if authDetails != nil && authDetails?.type == "openid_credential" && authDetails?.credentialIdentifiers != nil {
                    params = [
                        "credential_identifier": authDetails?.credentialIdentifiers?.first,
                        "proof": [
                            "proof_type": "jwt",
                            "jwt": idToken
                        ]
                    ]
            } else if authDetails != nil && authDetails?.type == "openid_credential" && authDetails?.credentialConfigId != nil && issuerConfig.nonceEndPoint != nil {
                params = [
                    "credential_configuration_id": authDetails?.credentialConfigId,
                    "proof": [
                        "proof_type": "jwt",
                        "jwt": idToken
                    ]
                ]
            } else if tokenResponse?.cNonce == nil && authDetails == nil && issuerConfig.nonceEndPoint != nil {
                params = [
                    "credential_configuration_id": credentialTypes.first,
                    "proof": [
                        "proof_type": "jwt",
                        "jwt": idToken
                    ]
                ]
            } else if formatT == "mso_mdoc" {
                params = [
                    "doctype": doctType,
                    "format": formatT,
                    "proof": [
                        "proof_type": "jwt",
                        "jwt": idToken
                    ]
                ]
            } else {
                if types is String {
                    params = [
                        "vct": types ?? "",
                        "format": formatT ?? "jwt_vc",
                        "proof": [
                            "proof_type": "jwt",
                            "jwt": idToken
                        ]
                    ]
                }else{
                    params = [
                        "credential_definition": [
                            "type": types ?? []
                        ],
                        "format": formatT ?? "jwt_vc",
                        "proof": [
                            "proof_type": "jwt",
                            "jwt": idToken
                        ]
                    ]
                }
                if issuerConfig.credentialsSupported?.version == "v1" {
                    params = [
                        "types": credentialTypes,
                        "format": formatT ?? "jwt_vc",
                        "proof": [
                            "proof_type": "jwt",
                            "jwt": idToken
                        ]
                    ]
                } else {
                    if let data = issueHandler.getTypesFromIssuerConfig(issuerConfig: issuerConfig, type: credentialTypes.last ?? "") {
                        if let dataArray = data as? [String] {
                            params = [
                                "credential_definition": [
                                    "type": dataArray ?? []
                                ],
                                "format": formatT ?? "jwt_vc",
                                "proof": [
                                    "proof_type": "jwt",
                                    "jwt": idToken
                                ]
                            ]
                        } else if let dataString = data as? String {
                            params = [
                                "vct": dataString,
                                "format": formatT ?? "jwt_vc",
                                "proof": [
                                    "proof_type": "jwt",
                                    "jwt": idToken
                                ]
                            ]
                        }
                    }
                }
            }
            
            if issuerConfig.credentialRequestEncryption != nil {
                params.removeValue(forKey: "proof")
                var proofsDict: [String: Any] = [:]
                proofsDict["jwt"] = [idToken]
                params["proofs"] = proofsDict
            }
            
            if issuerConfig.credentialResponseEncryption != nil && issuerConfig.credentialResponseEncryption?.algValuesSupported?.contains("ECDH-ES") == true && issuerConfig.credentialResponseEncryption?.encValuesSupported?.contains("A128CBC-HS256") == true {
                let jwk = JWEEncryptor().generateEphemeralEncryptionJWK(privateKey: privateKey)
                params["credential_response_encryption"] = ["jwk": jwk, "alg": "ECDH-ES", "enc": "A128CBC-HS256"]
            }
            // Create URL for the credential endpoint
            guard let url = URL(string: issuerConfig.credentialEndpoint ?? "") else { return nil }
            
            // Set up the request for the credential endpoint
            request = URLRequest(url: url)
            if issuerConfig.credentialRequestEncryption?.encryptionRequired == true  {
                request.setValue("application/jwt", forHTTPHeaderField: "Content-Type")
            } else {
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            }
            request.setValue( "Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
            request.httpMethod = "POST"
            if issuerConfig.credentialRequestEncryption?.encryptionRequired == true {
                let credentialRequestEncryptionJwks = issuerConfig.credentialRequestEncryption?.jwks?.first?.dictionary
                var encryptRequest = ""
                do {
                    encryptRequest = try await JWEEncryptor().encrypt(payload: params, jwks: credentialRequestEncryptionJwks)
                } catch {
                    encryptRequest = ""
                }
                // Convert the parameters to JSON data and set it as the request body
                let requestBodyData = encryptRequest.data(using: .utf8)
                request.httpBody =  requestBodyData
            } else {
                let requestBodyData = try? JSONSerialization.data(withJSONObject: params)
                request.httpBody =  requestBodyData
            }
            
            // Perform the request and handle the response
            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                let httpRes = response as? HTTPURLResponse
                if httpRes?.statusCode ?? 0 >= 400 {
                    let errorString = String(data: data, encoding: .utf8)
                    let error = EUDIError(from: ErrorResponse(message: errorString))
                    if let eudiErrorData = ErrorHandler.processError(data: data, contentType: httpRes?.value(forHTTPHeaderField: "Content-Type")) {
                        return CredentialResponse(fromError: eudiErrorData)
                    } else {
                        return CredentialResponse(fromError: error)
                    }
                }
                var jsonObject: [String: Any]?
                var responseData: Data?
                if httpRes?.value(forHTTPHeaderField: "Content-Type") == "application/jwt", let responseString = String(data: data, encoding: .utf8) {
                    if let decryptedData = JWEDecryptor().decrypt(responseString, privateKey: privateKey) {
                        jsonObject = try JSONSerialization.jsonObject(with: decryptedData.data(using: .utf8)!, options: []) as? [String: Any]
                        responseData = decryptedData.data(using: .utf8)!
                    }
                } else {
                    responseData = data
                    jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
                }
                guard let jsonObject = jsonObject, let responseData = responseData  else { return nil }
                if jsonObject["acceptance_token"] != nil {
                    let model = try jsonDecoder.decode(CredentialResponseV1.self, from: responseData)
                    return CredentialResponse(from: model)
                    
                } else if jsonObject["transaction_id"] != nil {
                    let modelV2 = try jsonDecoder.decode(CredentialResponseV2.self, from: responseData)
                    return CredentialResponse(from: modelV2)
                } else if jsonObject["acceptance_token"] == nil && jsonObject["transaction_id"] == nil {
                    let model = try jsonDecoder.decode(CredentialResponseV1.self, from: responseData)
                    return CredentialResponse(from: model)
                } else {
                    //let error = EUDIError(from: ErrorResponse(message: "Invalid data format", code: nil))
                    let error = ErrorHandler.processError(data: data, contentType: httpRes?.value(forHTTPHeaderField: "Content-Type"))
                    return CredentialResponse(fromError: error ?? EUDIError(from: ErrorResponse(message: "Invalid data format", code: nil)))
                }
            } catch {
                debugPrint("Process credential request failed: \(error)")
                let nsError = error as NSError
                let errorCode = nsError.code
                let error = EUDIError(from: ErrorResponse(message:error.localizedDescription, code: errorCode))
                return CredentialResponse(fromError: error)
            }
        }
    
}

