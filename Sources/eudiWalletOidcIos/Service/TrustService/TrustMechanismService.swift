//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 11/06/25.
//

import Foundation

public class TrustMechanismService: TrustMechanismServiceProtocol {
    
    public static var shared = TrustMechanismService()
    public init() {}
    
    public func isIssuerOrVerifierTrusted(url: String?, x5c: String?, jwksURI: String?, completion: @escaping (Bool?) -> Void){
        var isValidOrganization: Bool? = nil
        var validationResults: [Bool?] = []
        parseXmlDataToJson(url: url) { data in
            if let data = data {
                for item in data.trustServiceProviders ?? [] {
                    for service in item.tspServices {
                        if let identities = service.serviceDigitalIdentities {
                            for identity in identities {
                                if identity.x509Certificate == x5c {
                                    validationResults.append(true)
                                
                                } else if identity.x509SKI == x5c {
                                    validationResults.append(true)
                                } else if identity.DID == x5c {
                                    validationResults.append(true)
                                } else if identity.KID == x5c && identity.JwksURI == jwksURI {
                                    validationResults.append(true)
                                } else if identity.KID == x5c {
                                    validationResults.append(true)
                                }
                            }
                        }
                    }
                }
                if validationResults.contains(true) {
                    completion(true)
                } else {
                    completion(nil)
                }
            } else {
                completion(nil)
            }
            
        }
    }

public func fetchTrustDetails(url: String?, x5c: String?, jwksURI: String?, completion: @escaping (TrustServiceProvider?) -> Void) {
    parseXmlDataToJson(url: url) { data in
        guard let data = data else {
            completion(nil)
            return
        }

        for item in data.trustServiceProviders ?? [] {
            for service in item.tspServices {
                let hasMatchingId = service.serviceDigitalIdentities?.contains {
                    $0.x509Certificate == x5c || $0.x509SKI == x5c || ($0.KID == x5c && $0.JwksURI == jwksURI) || $0.DID == x5c
                } ?? false

                if hasMatchingId {
                    var matchedTSP = item
                    matchedTSP.tspServices = [service]
                    completion(matchedTSP)
                    return
                }
            }
        }

        completion(nil)
    }
}
    
    public func parseXmlDataToJson(url: String?, completion: @escaping (TrustServiceStatusList?) -> Void) {
        guard let urlStr = url, let fetchURL = URL(string: urlStr) else {
            DispatchQueue.main.async { completion(nil) }
            return
        }
        URLSession.shared.dataTask(with: fetchURL) { data, response, error in
            guard let data = data, error == nil else {
                print("Error fetching XML: \(error?.localizedDescription ?? "Unknown error")")
                return
            }
            let parser = XMLToJSONParser()
            parser.parse(xmlData: data) { result in
                switch result {
                case .success(let jsonData):
                    if let jsonString = String(data: jsonData, encoding: .utf8) {
                        do {
                            if let jsonData = jsonString.data(using: .utf8) {
                                let decoder = JSONDecoder()
                                let trustServiceList = try decoder.decode(TrustServiceStatusList.self, from: jsonData)
                                completion(trustServiceList)
                            }
                        } catch {
                            completion(nil)
                        }
                    }
                case .failure(let error):
                    completion(nil)
                }
            }
            
        }.resume()
    }
    
}
