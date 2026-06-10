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
    
    
    /// Searches for a matching `TrustServiceProvider` for a given credential identifier
    /// within the EWC trust list.
    ///
    /// If a pre-fetched `data` is provided (e.g. from `TrustListCache`), the search is
    /// performed entirely in memory with no network call. If `data` is `nil`, the trust
    /// list is fetched from the given `url` before searching.
    ///
    /// The match is attempted against the following identity fields in order:
    /// `x509Certificate` → `x509SKI` → `KID + JwksURI` → `DID` → `KID`
    ///
    /// - Parameters:
    ///   - url: The URL of the EWC trust list XML. Used only when `data` is `nil` to fetch the list from network.
    ///   - data: An optional pre-fetched `TrustServiceStatusList`. If provided, skips the network call entirely.
    ///   - x5c: The credential identifier to match against — can be an x509 certificate, SKI, KID, or DID.
    ///   - jwksURI: The JWKS URI used alongside `KID` for KID-based matching.
    ///   - completion: Called on completion with the matched `TrustServiceProvider` containing only
    ///                 the matched service, or `nil` if no match was found.
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
        fetchAndParseTrustList(url: url) { fetched in
            guard let fetched = fetched else { completion(nil); return }
            search(fetched)
        }
    }
}

    /// Checks whether an issuer or verifier is present and trusted in the EWC trust list
    /// for a given credential identifier.
    ///
    /// If a pre-fetched `data` is provided (e.g. from `TrustListCache`), the validation is
    /// performed entirely in memory with no network call. If `data` is `nil`, the trust
    /// list is fetched from the given `url` before validating.
    ///
    /// The identifier is matched against the following identity fields:
    /// `x509Certificate`, `x509SKI`, `DID`, `KID + JwksURI`, `KID`
    ///
    /// - Parameters:
    ///   - url: The URL of the EWC trust list XML. Used only when `data` is `nil` to fetch the list from network.
    ///   - data: An optional pre-fetched `TrustServiceStatusList`. If provided, skips the network call entirely.
    ///   - x5c: The credential identifier to validate — can be an x509 certificate, SKI, KID, or DID.
    ///   - jwksURI: The JWKS URI used alongside `KID` for KID-based matching.
    ///   - completion: Called on completion with `true` if the identifier was found in the trust list,
    ///                 or `nil` if not found or if the trust list could not be loaded.
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
            fetchAndParseTrustList(url: url) { fetched in
                guard let fetched = fetched else { completion(nil); return }
                validate(fetched)
            }
        }
    }
    
    /// Fetches the EWC trust list XML from the given URL, parses it, and decodes it
    /// into a `TrustServiceStatusList` model.
    /// - Parameters:
    ///   - url: The remote URL of the EWC trust list XML file.
    ///   - completion: Called on completion with the decoded `TrustServiceStatusList`,
    ///                 or `nil` if the URL is invalid, the request fails, or decoding fails.
    public func fetchAndParseTrustList(url: String?, completion: @escaping (TrustServiceStatusList?) -> Void) {
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
