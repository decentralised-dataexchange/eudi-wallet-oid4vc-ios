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

    /// Path of the lookup endpoint, appended to `baseURL`. Overridable because the host publishes
    /// it in metadata alongside the base URL.
    public static var lookupPath: String = "/trust-list/lookup"

    /// Optionally override the trust-list endpoint (e.g. test vs prod). `lookupPath` is left
    /// unchanged when nil, so existing callers keep the default path.
    public static func configure(baseURL: String, lookupPath: String? = nil) {
        ServerTrustMechanismService.baseURL = baseURL
        if let lookupPath = lookupPath, !lookupPath.trimmingCharacters(in: .whitespaces).isEmpty {
            ServerTrustMechanismService.lookupPath = lookupPath
        }
    }

    /// Joins base and path tolerantly — either side may or may not carry the separating slash.
    private var lookupURL: String {
        let base = ServerTrustMechanismService.baseURL.hasSuffix("/")
            ? String(ServerTrustMechanismService.baseURL.dropLast())
            : ServerTrustMechanismService.baseURL
        let path = ServerTrustMechanismService.lookupPath.hasPrefix("/")
            ? ServerTrustMechanismService.lookupPath
            : "/\(ServerTrustMechanismService.lookupPath)"
        return base + path
    }

    // `data` mirrors the protocol; the server lookup ignores it (no in-memory list).
    public func isIssuerOrVerifierTrusted(url: String?,
                                          data: TrustServiceStatusList? = nil,
                                          x5c: String?,
                                          jwksURI: String?,
                                          completion: @escaping (Bool?) -> Void) {
        lookup(identifier: x5c) { response in
            // Return true on match, nil otherwise — matches TrustMechanismService's semantics so
            // callers (e.g. FilterCredentialService) can `.contains(true)`. A match whose services
            // are all withdrawn is not trusted.
            let trusted = response?.match == true && response?.grantedEntries.isEmpty == false
            completion(trusted ? true : nil)
        }
    }

    public func fetchTrustDetails(url: String?,
                                  data: TrustServiceStatusList? = nil,
                                  x5c: String?,
                                  jwksURI: String?,
                                  completion: @escaping (TrustServiceProvider?) -> Void) {
        lookup(identifier: x5c) { response in
            guard let response = response, response.match else {
                completion(nil)
                return
            }
            let granted = response.grantedEntries
            guard !granted.isEmpty else {
                self.logDroppedEntries(response)
                completion(nil)
                return
            }
            self.logDroppedEntries(response)
            completion(self.mapToTrustServiceProvider(granted))
        }
    }

    /// Looks up `identifier` and returns the URLs of every trust list it matched (empty if none).
    /// Used to filter credentials against a DCQL request's `trusted_authorities` (etsi_tl URLs) —
    /// one identifier can be listed in several trust lists, so the caller must intersect rather than
    /// compare against a single URL.
    public func matchedTrustListURLs(x5c: String?, completion: @escaping ([String]) -> Void) {
        lookup(identifier: x5c) { response in
            guard let response = response, response.match else {
                completion([])
                return
            }
            completion(response.grantedEntries.compactMap { $0.trustList?.url })
        }
    }

    /// Logs entries refused because their service status is not `granted`, so a "not trusted" result
    /// is traceable to a withdrawn (or unparseable) status rather than looking like a failed lookup.
    private func logDroppedEntries(_ response: TrustListLookupResponse) {
        let dropped = response.matchedEntries.filter { !$0.serviceStatus.isTrusted }
        guard !dropped.isEmpty else { return }
        for entry in dropped {
            print("TrustLookup: dropped entry '\(entry.service?.serviceTypeIdentifier ?? "-")' from '\(entry.trustList?.url ?? "-")' — status=\(entry.serviceStatus.rawValue) (raw=\(entry.service?.serviceStatus ?? entry.status ?? "nil"))")
        }
    }

    /// First matched trust-list URL. Prefer `matchedTrustListURLs` — an identifier present in
    /// several trust lists returns several, and picking the first can miss the requested one.
    public func matchedTrustListURL(x5c: String?, completion: @escaping (String?) -> Void) {
        matchedTrustListURLs(x5c: x5c) { completion($0.first) }
    }

    /// POST /trust-list/lookup (open endpoint). Fail-closed to nil.
    ///
    /// Every lookup is logged with the input it was given — which identifier kind was sent and the
    /// (abbreviated) value — so a trust decision can always be traced back to what was asked.
    private func lookup(identifier: String?, completion: @escaping (TrustListLookupResponse?) -> Void) {
        guard let identifier = identifier, !identifier.isEmpty,
              let url = URL(string: lookupURL) else {
            print("TrustLookup ▶︎ SKIPPED — no identifier supplied (failing closed)")
            completion(nil)
            return
        }

        let body = buildLookupBody(identifier: identifier)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONEncoder().encode(body)

        let requestID = UUID().uuidString.prefix(8)
        print("TrustLookup ▶︎ [\(requestID)] POST \(lookupURL)")
        print("TrustLookup ▶︎ [\(requestID)] input: kind=\(Self.describeKind(body)) value=\(Self.abbreviate(identifier)) (len=\(identifier.count))")
        if let bodyString = request.httpBody.flatMap({ String(data: $0, encoding: .utf8) }) {
            print("TrustLookup ▶︎ [\(requestID)] body: \(Self.abbreviate(bodyString, limit: 300))")
        }

        let startedAt = Date()
        URLSession.shared.dataTask(with: request) { data, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            let elapsed = String(format: "%.0fms", Date().timeIntervalSince(startedAt) * 1000)
            let decoded = data.flatMap { try? JSONDecoder().decode(TrustListLookupResponse.self, from: $0) }

            print("TrustLookup ◀︎ [\(requestID)] status=\(status) in \(elapsed)\(error.map { " error=\($0.localizedDescription)" } ?? "")")
            if let bodyString = data.flatMap({ String(data: $0, encoding: .utf8) }) {
                print("TrustLookup ◀︎ [\(requestID)] response: \(Self.abbreviate(bodyString, limit: 1200))")
            }

            guard error == nil, (200..<300).contains(status), let decoded = decoded else {
                print("TrustLookup ◀︎ [\(requestID)] FAILED (decode=\(decoded == nil ? "nil" : "ok")) — not trusted")
                completion(nil)
                return
            }

            let summary = decoded.matchedEntries.map {
                "\($0.service?.serviceTypeIdentifier ?? "-")[\($0.serviceStatus.rawValue)]@\($0.trustList?.name ?? $0.trustList?.url ?? "-")"
            }
            print("TrustLookup ◀︎ [\(requestID)] match=\(decoded.match) entries=\(decoded.matchedEntries.count) granted=\(decoded.grantedEntries.count) \(summary)")
            completion(decoded)
        }.resume()
    }

    /// Which identifier field the body ended up using — the thing that most often explains a miss.
    private static func describeKind(_ body: TrustListLookupRequest) -> String {
        if body.x5c != nil { return "x5c" }
        if body.did != nil { return "did" }
        if body.jwksUri != nil { return "jwksUri" }
        return "kid"
    }

    /// Keeps log lines readable (and certs/DIDs out of the log in full) while staying identifiable.
    private static func abbreviate(_ value: String, limit: Int = 48) -> String {
        guard value.count > limit else { return value }
        let head = value.prefix(limit / 2)
        let tail = value.suffix(8)
        return "\(head)…\(tail)"
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

    /// Maps the matched OWS Trust List entries onto the `TrustServiceProvider` the detail UI reads.
    /// Provider identity/address come from the first entry; every entry contributes one service, so
    /// callers can see all service types (and roles) the identifier matched.
    private func mapToTrustServiceProvider(_ entries: [TrustListEntry]) -> TrustServiceProvider {
        guard let first = entries.first else {
            return TrustServiceProvider(tspName: "", tspTradeName: nil, tspInformationURI: nil, tspAddress: nil, tspServices: [])
        }
        var result = mapToTrustServiceProvider(first)
        result.tspServices = entries.map { mapToTSPService($0) }
        return result
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

        return TrustServiceProvider(tspName: provider?.tSPName ?? "",
                                    tspTradeName: provider?.tSPTradeName,
                                    tspInformationURI: provider?.tSPInformationURI,
                                    tspAddress: address,
                                    tspServices: [mapToTSPService(entry)])
    }

    /// Maps one entry's `service` section (plus its accreditation) onto a `TSPService`.
    private func mapToTSPService(_ entry: TrustListEntry) -> TSPService {
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
        return TSPService(serviceTypeIdentifier: service?.serviceTypeIdentifier ?? "",
                          serviceName: service?.serviceName ?? "",
                          serviceStatus: service?.serviceStatus ?? "",
                          statusStartingTime: service?.statusStartingTime,
                          serviceDigitalIdentities: digitalIdentities,
                          serviceSupplyPoints: nil,
                          permittedCredentials: entry.permittedCredentials?.items ?? [],
                          prohibitedCredentials: entry.prohibitedCredentials?.items ?? [])
    }
}
