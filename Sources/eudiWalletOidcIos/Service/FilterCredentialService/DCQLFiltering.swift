//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 10/07/25.
//

import Foundation
import PresentationExchangeSdkiOS

public class DCQLFiltering {

    public static func filterCredentialsUsingDCQL(dcql: DCQLQuery?, credentials: [String?]) -> [[MatchedCredential]] {
        var filteredList: [[MatchedCredential]] = []

        guard let credentialFilters = dcql?.credentials else {
            return filteredList
        }

        for credentialFilter in credentialFilters {
            let result = filterCredentialUsingSingleDCQLCredentialFilter(credentialFilter: credentialFilter, credentialList: credentials)
            filteredList.append(result)
        }

        return filteredList
    }

    public static func filterCredentialUsingSingleDCQLCredentialFilter(
        credentialFilter: CredentialItems,
        credentialList: [String?]
    ) -> [MatchedCredential] {
        var filteredList: [MatchedCredential] = []
        if credentialFilter.format == "dc+sd-jwt" || credentialFilter.format == "vc+sd-jwt" {
            let updatedCredentials = FilterCredentialService().processCredentialsToJsonString(credentialList: credentialList)
            credentialLoop: for (credentialIndex, credentialString) in updatedCredentials.enumerated() {
                guard let credentialData = credentialString.data(using: .utf8),
                      let credentialJSON = try? JSONSerialization.jsonObject(with: credentialData) as? [String: Any] else {
                    continue
                }

                var matchedFields: [MatchedField] = []

                // Extract vct values from Meta
                var vctValues: [String]? = nil
                if case .dcSDJWT(let meta) = credentialFilter.meta {
                    vctValues = meta.vctValues
                }
                let vct = credentialJSON["vct"] as? String
                if vct == nil {
                    continue
                }
                

                if let vct = credentialJSON["vct"] as? String, !vct.isEmpty,
                   let vctValues = vctValues, !vctValues.contains(vct) {
                    continue
                }
                
                guard let claims = credentialFilter.claims else {
                    filteredList.append(
                        MatchedCredential(index: credentialIndex, fields: [])
                    )
                    continue
                }
                for (pathIndex, claim) in claims.enumerated() {
                    guard case .pathClaim(let pathClaim) = claim else { continue }
                    let paths = pathClaim.path
                    let nonNilPaths = paths.compactMap { $0 }
                    let joinedPath = nonNilPaths.joined(separator: ",")
                    
                    guard let matchedValue = getValue(from: credentialJSON, forPath: joinedPath) else {
                        continue credentialLoop
                    }
                    
                    matchedFields.append(MatchedField(
                        index: credentialIndex,
                        path: MatchedPath(path: joinedPath, index: pathIndex, value: matchedValue)
                    ))
                }
                
                filteredList.append(MatchedCredential(index: credentialIndex, fields: matchedFields))
            }
            
        } else if  credentialFilter.format == "jwt_vc_json" {
            
            let updatedCredentials = FilterCredentialService().processCredentialsToJsonString(credentialList: credentialList)
            credentialLoop: for (credentialIndex, credentialString) in updatedCredentials.enumerated() {
                guard let credentialData = credentialString.data(using: .utf8),
                      let credentialJSON = try? JSONSerialization.jsonObject(with: credentialData) as? [String: Any] else {
                    continue
                }
                
                var matchedFields: [MatchedField] = []
                
                var typeValues: [[String]]? = nil
                if case .jwt(let meta) = credentialFilter.meta {
                    typeValues = meta.typeValues
                }
                
                if credentialJSON["type"] == nil {
                    continue
                }
                
                if let types = credentialJSON["type"] as? [String],
                   let typeValues = typeValues {
                    let hasCommonType = typeValues.contains { innerArray in
                        !Set(innerArray).isDisjoint(with: Set(types))
                    }
                    
                    if !hasCommonType {
                        continue
                    }
                }
                guard let claims = credentialFilter.claims else {
                    filteredList.append(
                        MatchedCredential(index: credentialIndex, fields: [])
                    )
                    continue
                }
                for (pathIndex, claim) in claims.enumerated() {
                    guard case .pathClaim(let pathClaim) = claim else { continue }
                    let paths = pathClaim.path
                    let nonNilPaths = paths.compactMap { $0 }
                    let joinedPath = nonNilPaths.joined(separator: ",")
                    
                    guard let matchedValue = getValue(from: credentialJSON, forPath: joinedPath) else {
                        continue credentialLoop
                    }
                    
                    matchedFields.append(MatchedField(
                        index: credentialIndex,
                        path: MatchedPath(path: joinedPath, index: pathIndex, value: matchedValue)
                    ))
                }
                
                filteredList.append(MatchedCredential(index: credentialIndex, fields: matchedFields))
            }
            
        } else if credentialFilter.format == "mso_mdoc" {
            let updatedCredentials = FilterCredentialService().processCborCredentialToJsonString(credentialList: credentialList)
            credentialLoop: for (credentialIndex, credentialString) in updatedCredentials.enumerated() {
                guard let credentialData = credentialString.data(using: .utf8),
                      let credentialJSON = try? JSONSerialization.jsonObject(with: credentialData) as? [String: Any] else {
                    continue
                }
                var docType = ""
                if let issuerAuth = MDocVpTokenBuilder().getIssuerAuth(credential: credentialList[credentialIndex] ?? "") {
                     docType = MDocVpTokenBuilder().getDocTypeFromIssuerAuth(cborData: issuerAuth) ?? ""
                }
                var matchedFields: [MatchedField] = []
                
                var docTypeValue: String? = nil
                if case .msoMdoc(let meta) = credentialFilter.meta {
                    docTypeValue = meta.doctypeValue
                }
                
                guard let claims = credentialFilter.claims else {
                    if docType == docTypeValue ?? "" {
                        filteredList.append(
                            MatchedCredential(index: credentialIndex, fields: [])
                        )
                    }
                    continue
                }
                for (pathIndex, claim) in claims.enumerated() {
                    switch claim {
                      case .namespacedClaim(let namespacedClaim):
                        let namespace = namespacedClaim.namespace
                        let claimName = namespacedClaim.claimName

                        guard !namespace.isEmpty, !claimName.isEmpty else {
                            continue credentialLoop
                        }

                        guard let namespaceDict = credentialJSON[namespace] as? [String: Any],
                              let value = namespaceDict[claimName] else {
                            continue credentialLoop
                        }

                        matchedFields.append(MatchedField(
                            index: credentialIndex,
                            path: MatchedPath(path: "\(namespace).\(claimName)", index: pathIndex, value: value)
                        ))
                    case .pathClaim(let pathClaim):
                        let paths = pathClaim.path
                    let nonNilPaths = paths.compactMap { $0 }
                        let joinedPath = nonNilPaths.joined(separator: ",")

                        guard let matchedValue = getValue(from: credentialJSON, forPath: joinedPath) else {
                            continue credentialLoop
                        }

                        matchedFields.append(MatchedField(
                            index: credentialIndex,
                            path: MatchedPath(path: joinedPath, index: pathIndex, value: matchedValue)
                        ))
                        
                    default:
                            continue
                    }
                    
                }

                filteredList.append(MatchedCredential(index: credentialIndex, fields: matchedFields))
            }
        }

        return filteredList
    }

     private static func getValue(from json: [String: Any], forPath path: String) -> Any? {
        let keys = path.split(separator: ",").map { String($0) }
        var current: Any = json

        for key in keys {
            if let dict = current as? [String: Any], let next = dict[key] {
                current = next
            } else if let stringValue = current as? String, /*let sanitisedString = sanitizeToJson(stringValue),*/ let innerDict = UIApplicationUtils.shared.convertStringToDictionary(text: stringValue), let reslut = innerDict[key]{
                current = reslut
            } else {
                return nil
            }
        }
        return current
    }
    
}
