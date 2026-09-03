//
//  RemoteCredentialOfferSource.swift
//  eudiWalletOidcIos
//

import Foundation

/// The link points at the offer: `?credential_offer_uri=<https URL>`.
///
/// OpenID4VCI 1.0 section 4.1.3: the wallet MUST fetch it with an HTTP GET, and the response
/// "MUST use the media type `application/json`".
struct RemoteCredentialOfferSource: CredentialOfferSource {

    let name = "credential_offer_uri"

    /// Injectable so the fetch can be stubbed with a `URLProtocol` in tests.
    let session: URLSession

    init(session: URLSession = .shared) {
        self.session = session
    }

    private static let parameter = "credential_offer_uri"

    func supports(_ data: String) -> Bool {
        let value = OfferURI.queryParameter(Self.parameter, in: data)
        return !(value ?? "").isEmpty
    }

    func retrieve(_ data: String, policy: CredentialOfferPolicy) async throws -> Data {
        guard let uri = OfferURI.queryParameter(Self.parameter, in: data), !uri.isEmpty else {
            throw CredentialOfferError.noOffer
        }

        let scheme = OfferURI.scheme(of: uri)
        guard policy.allows(scheme: scheme) else {
            throw CredentialOfferError.unsupportedScheme(scheme)
        }
        guard let url = URL(string: uri) else {
            throw CredentialOfferError.malformed("The credential offer link is not a valid address")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await NetworkLogger.send(request, tag: "credential-offer", session: session)
        } catch {
            throw CredentialOfferError.fetchFailed(status: nil, detail: error.localizedDescription)
        }

        let http = response as? HTTPURLResponse
        if let status = http?.statusCode, status >= 400 {
            let body = String(data: data, encoding: .utf8)
            throw CredentialOfferError.fetchFailed(status: status, detail: body?.isEmpty == false ? body : nil)
        }

        let contentType = http?.value(forHTTPHeaderField: "Content-Type")
        if policy.requireJSONContentType, !Self.isJSON(contentType) {
            throw CredentialOfferError.notJSON(contentType: contentType)
        }
        if Self.isJWT(contentType) {
            throw CredentialOfferError.signedOfferRejected
        }
        guard data.count <= policy.maxOfferBytes else {
            throw CredentialOfferError.tooLarge(bytes: data.count)
        }
        guard !data.isEmpty else {
            throw CredentialOfferError.fetchFailed(status: http?.statusCode, detail: "The credential offer was empty")
        }
        return data
    }

    private static func mediaType(_ contentType: String?) -> String? {
        contentType?.components(separatedBy: ";").first?
            .trimmingCharacters(in: .whitespaces).lowercased()
    }

    private static func isJSON(_ contentType: String?) -> Bool {
        guard let type = mediaType(contentType) else { return false }
        return type == "application/json" || type.hasSuffix("+json")
    }

    private static func isJWT(_ contentType: String?) -> Bool {
        mediaType(contentType) == "application/jwt"
    }
}
