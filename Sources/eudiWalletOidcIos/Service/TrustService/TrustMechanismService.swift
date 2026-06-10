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
    
    public func fetchTrustDetails(url: String?, data: TrustServiceStatusList? = nil, x5c: String?, jwksURI: String?, completion: @escaping (TrustServiceProvider?) -> Void) {
    
    func search(_ trustList: TrustServiceStatusList) {
        for item in trustList.trustServiceProviders ?? [] {
            for service in item.tspServices {
                let hasMatchingId = service.serviceDigitalIdentities?.contains {
                    $0.x509Certificate == x5c ||
                    $0.x509SKI == x5c ||
                    ($0.KID == x5c && $0.JwksURI == jwksURI) ||
                    $0.DID == x5c ||
                    $0.KID == x5c
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
    
    if let data = data {
        search(data)
    } else {
        parseXmlDataToJson(url: url) { fetched in
            guard let fetched = fetched else { completion(nil); return }
            search(fetched)
        }
    }
}

public func isIssuerOrVerifierTrusted(url: String?, data: TrustServiceStatusList? = nil, x5c: String?, jwksURI: String?, completion: @escaping (Bool?) -> Void) {
    
    func validate(_ trustList: TrustServiceStatusList) {
        var validationResults: [Bool] = []
        for item in trustList.trustServiceProviders ?? [] {
            for service in item.tspServices {
                if let identities = service.serviceDigitalIdentities {
                    for identity in identities {
                        if identity.x509Certificate == x5c ||
                           identity.x509SKI == x5c ||
                           identity.DID == x5c ||
                           (identity.KID == x5c && identity.JwksURI == jwksURI) ||
                           identity.KID == x5c {
                            validationResults.append(true)
                        }
                    }
                }
            }
        }
        completion(validationResults.contains(true) ? true : nil)
    }
    
    if let data = data {
        validate(data)
    } else {
        parseXmlDataToJson(url: url) { fetched in
            guard let fetched = fetched else { completion(nil); return }
            validate(fetched)
        }
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
