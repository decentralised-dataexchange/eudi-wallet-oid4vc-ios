//
//  ServerTrustMechanismService.swift
//  eudiWalletOidcIos
//
//  Server-backed implementation of `TrustMechanismServiceProtocol` that evaluates trust against the
//  OWS Trust List backend, instead of the local/static EU TSL XML used by `TrustMechanismService`.
//
//  The lookup endpoint is open — a single POST {baseURL}/trust-list/lookup with the verifier/issuer
//  identifier (x5c / kid / did / jwksUri). No device auth. iOS counterpart of the Android SDK's
//  ServerTrustMechanismService.
//
//  Fail-closed: any failure resolves to "not trusted".
//

import Foundation
import Security

public class ServerTrustMechanismService: TrustMechanismServiceProtocol {

    public static let shared = ServerTrustMechanismService()
    public init() {}

    // TODO(trust-api): TEST/PROD base URL. Override with `configure(baseURL:)`.
    public static var baseURL: String = "https://trustlist.nxd.foundation"

    /// TrustEvaluator/FilterCredentialService combines a kid with its jwksUri as "kid##SEP##jwksUri".
    private static let kidJwksSeparator = "##SEP##"

    /// Optionally override the trust-list base URL (e.g. test vs prod).
    public static func configure(baseURL: String) {
        ServerTrustMechanismService.baseURL = baseURL
    }

    private var lookupURL: String { "\(ServerTrustMechanismService.baseURL)/trust-list/lookup" }

    // `data` mirrors the protocol; the server lookup ignores it (no in-memory list).
    public func isIssuerOrVerifierTrusted(url: String?,
                                          data: TrustServiceStatusList? = nil,
                                          x5c: String?,
                                          jwksURI: String?,
                                          completion: @escaping (Bool?) -> Void) {
        lookup(identifier: x5c) { response in
            // Return true on match, nil otherwise — matches TrustMechanismService's semantics so
            // callers (e.g. FilterCredentialService) can `.contains(true)`.
            completion(response?.match == true ? true : nil)
        }
    }

    public func fetchTrustDetails(url: String?,
                                  data: TrustServiceStatusList? = nil,
                                  x5c: String?,
                                  jwksURI: String?,
                                  completion: @escaping (TrustServiceProvider?) -> Void) {
        lookup(identifier: x5c) { response in
            guard let response = response, response.match, let entry = response.entry else {
                completion(nil)
                return
            }
            completion(self.mapToTrustServiceProvider(entry))
        }
    }

    /// Looks up `identifier` and returns the URL of the trust list it matched (or nil if no match).
    /// Used to filter credentials against a DCQL request's `trusted_authorities` (etsi_tl URLs).
    public func matchedTrustListURL(x5c: String?, completion: @escaping (String?) -> Void) {
        lookup(identifier: x5c) { response in
            guard let response = response, response.match else {
                completion(nil)
                return
            }
            completion(response.entry?.trustList?.url)
        }
    }

    /// POST /trust-list/lookup (open endpoint). Fail-closed to nil.
    private func lookup(identifier: String?, completion: @escaping (TrustListLookupResponse?) -> Void) {
        guard let identifier = identifier, !identifier.isEmpty,
              let url = URL(string: lookupURL) else {
            completion(nil)
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONEncoder().encode(buildLookupBody(identifier: identifier))

        URLSession.shared.dataTask(with: request) { data, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            let decoded = data.flatMap { try? JSONDecoder().decode(TrustListLookupResponse.self, from: $0) }

            guard error == nil, (200..<300).contains(status), let decoded = decoded else {
                completion(nil)
                return
            }
            completion(decoded)
        }.resume()
    }

    /// Maps whatever identifier the caller supplies onto the correct request field — an x5c cert, a
    /// plain kid, a DID, or a "kid##SEP##jwksUri" combined key.
    private func buildLookupBody(identifier: String) -> TrustListLookupRequest {
        if identifier.contains(ServerTrustMechanismService.kidJwksSeparator) {
            let kid = identifier.components(separatedBy: ServerTrustMechanismService.kidJwksSeparator).first
            return TrustListLookupRequest(kid: kid)
        } else if identifier.hasPrefix("did:") {
            return TrustListLookupRequest(did: identifier)
        } else if isX509Certificate(identifier) {
            return TrustListLookupRequest(x5c: [identifier])
        } else {
            return TrustListLookupRequest(kid: identifier)
        }
    }

    /// True if `value` is a base64-DER X.509 certificate (i.e. an x5c), false for a kid/DID string.
    private func isX509Certificate(_ value: String) -> Bool {
        guard let der = Data(base64Encoded: value) else { return false }
        return SecCertificateCreateWithData(nil, der as CFData) != nil
    }

    /// Maps the flat OWS Trust List `entry` onto the `TrustServiceProvider` the detail UI reads.
    private func mapToTrustServiceProvider(_ entry: TrustListEntry) -> TrustServiceProvider {
        let provider = entry.provider
        let postal = PostalAddress(streetAddress: provider?.streetAddress,
                                   locality: provider?.locality,
                                   stateOrProvince: nil,
                                   postalCode: provider?.postalCode,
                                   countryName: provider?.countryName)
        let electronic = provider?.electronicAddress.map { ElectronicAddress(uri: $0) }
        let address = TSPAddress(postalAddresses: [postal], electronicAddresses: electronic)

        let service = entry.service
        let cert = service?.digitalIdentity?.first?
            .replacingOccurrences(of: "\\s", with: "", options: .regularExpression)
        let details = entry.certificateDetails
        let matchedIndex = entry.matchedCertIndex ?? 0
        let subjectKeyIdentifier = (details.flatMap { $0.indices.contains(matchedIndex) ? $0[matchedIndex] : $0.first })?.subjectKeyIdentifier
        // Non-empty did / kid / jwksURI from the matched service (the new response carries these).
        let did = (service?.did?.isEmpty == false) ? service?.did : nil
        let kid = (service?.kid?.isEmpty == false) ? service?.kid : nil
        let jwksURI = (service?.jwksURI?.isEmpty == false) ? service?.jwksURI : nil
        let hasIdentity = cert != nil || subjectKeyIdentifier != nil || did != nil || kid != nil || jwksURI != nil
        let digitalIdentities: [DigitalId]? = hasIdentity
            ? [DigitalId(x509Certificate: cert, x509SKI: subjectKeyIdentifier, x509SubjectName: nil, DID: did, KID: kid, JwksURI: jwksURI)]
            : nil
        let tspService = TSPService(serviceTypeIdentifier: service?.serviceTypeIdentifier ?? "",
                                    serviceName: service?.serviceName ?? "",
                                    serviceStatus: service?.serviceStatus ?? "",
                                    statusStartingTime: service?.statusStartingTime,
                                    serviceDigitalIdentities: digitalIdentities,
                                    serviceSupplyPoints: nil)

        return TrustServiceProvider(tspName: provider?.tSPName ?? "",
                                    tspTradeName: provider?.tSPTradeName,
                                    tspInformationURI: provider?.tSPInformationURI,
                                    tspAddress: address,
                                    tspServices: [tspService])
    }
}
