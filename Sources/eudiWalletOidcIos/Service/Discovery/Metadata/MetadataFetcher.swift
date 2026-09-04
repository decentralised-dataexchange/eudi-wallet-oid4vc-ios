//
//  MetadataFetcher.swift
//  eudiWalletOidcIos
//

import Foundation

/// A retrieved metadata document and the response metadata needed to interpret it.
struct MetadataDocument {
    let url: String
    let body: Data
    let contentType: String?

    private var mediaType: String? {
        contentType?.components(separatedBy: ";").first?
            .trimmingCharacters(in: .whitespaces).lowercased()
    }

    var isJWTMediaType: Bool { mediaType == "application/jwt" }

    var isJSONMediaType: Bool {
        guard let mediaType else { return false }
        return mediaType == "application/json" || mediaType.hasSuffix("+json")
    }
}

/// Retrieves a metadata document over HTTP.
///
/// Keeps the `HTTPURLResponse` rather than collapsing every failure into "nothing came back":
/// trying several well-known URLs means deciding which of several failures to report, and "404 on
/// the URL we tried last" is a far worse message than "403 on the URL the issuer actually uses".
enum MetadataFetcher {

    /// The `Accept` header to send, given whether the wallet can verify a signature.
    ///
    /// Section 12.2.2 treats Accept as "signaling whether it supports signed metadata", so a wallet
    /// that cannot verify one must not ask for it.
    static func acceptHeader(supportsSignedMetadata: Bool) -> String {
        supportsSignedMetadata ? "application/json, application/jwt" : "application/json"
    }

    /// The `Accept-Language` header to send, or `nil` when the policy disables it.
    static func acceptLanguageHeader(policy: DiscoveryPolicy) -> String? {
        guard policy.sendAcceptLanguage else { return nil }
        if let override = policy.acceptLanguage, !override.isEmpty { return override }
        let identifier = Locale.preferredLanguages.first ?? Locale.current.identifier
        return identifier.isEmpty ? nil : identifier
    }

    static func fetch(
        url urlString: String,
        tag: String,
        policy: DiscoveryPolicy,
        supportsSignedMetadata: Bool,
        session: URLSession
    ) async throws -> MetadataDocument {
        guard let url = URL(string: urlString) else {
            throw DiscoveryError.invalidIdentifier(urlString)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue(acceptHeader(supportsSignedMetadata: supportsSignedMetadata),
                         forHTTPHeaderField: "Accept")
        if let language = acceptLanguageHeader(policy: policy) {
            request.setValue(language, forHTTPHeaderField: "Accept-Language")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await NetworkLogger.send(request, tag: tag, session: session)
        } catch {
            throw DiscoveryError.fetchFailed(status: nil, detail: error.localizedDescription)
        }

        let http = response as? HTTPURLResponse
        if let status = http?.statusCode, status >= 400 {
            let body = String(data: data, encoding: .utf8)
            let detail = (body?.isEmpty == false && (body?.count ?? 0) <= 512) ? body : nil
            throw DiscoveryError.fetchFailed(status: status, detail: detail)
        }
        if let limit = policy.maxMetadataBytes, data.count > limit {
            throw DiscoveryError.tooLarge(bytes: data.count)
        }
        guard !data.isEmpty else {
            throw DiscoveryError.fetchFailed(status: http?.statusCode, detail: "The issuer configuration was empty")
        }

        return MetadataDocument(
            url: urlString,
            body: data,
            contentType: http?.value(forHTTPHeaderField: "Content-Type")
        )
    }

    /// `true` when `data` is shaped like a compact JWS.
    ///
    /// Checked in addition to the media type, because a document served as `application/json` that
    /// is in fact a JWT must still reach the verifier rather than be silently trusted.
    static func looksLikeJWT(_ data: Data) -> Bool {
        guard let text = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty
        else { return false }
        if text.hasPrefix("{") || text.hasPrefix("[") { return false }

        let parts = text.components(separatedBy: ".")
        guard parts.count == 3 else { return false }
        return parts.prefix(2).allSatisfy { part in
            !part.isEmpty && part.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == "=" }
        }
    }
}
