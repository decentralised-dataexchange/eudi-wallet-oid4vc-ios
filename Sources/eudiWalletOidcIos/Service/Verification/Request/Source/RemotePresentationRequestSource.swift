//
//  RemotePresentationRequestSource.swift
//  eudiWalletOidcIos
//

import Foundation
import JOSESwift

/// The request object sits behind a `request_uri`.
///
/// RFC 9101 section 5.2 fetches it with a GET. OpenID4VP 1.0 section 5.10 adds
/// `request_uri_method=post`: a form POST carrying the wallet's metadata and a fresh `wallet_nonce`
/// that the verifier MUST echo in the request object, which MAY come back encrypted to the key the
/// wallet sent. Section 5.10.2: any HTTP error from the verifier terminates the process.
struct RemotePresentationRequestSource: PresentationRequestSource {

    let name = "request_uri"
    let session: URLSession

    func supports(_ data: String) -> Bool {
        RequestUriMethod.requestUri(data) != nil
    }

    func retrieve(_ data: String, policy: PresentationRequestPolicy) async throws -> PresentationRequest {
        guard let requestUri = RequestUriMethod.requestUri(data) else { throw PresentationRequestError.noRequest }
        guard let url = URL(string: requestUri) else {
            throw PresentationRequestError.malformed("Invalid Request: request_uri is not a valid URL")
        }
        let clientIdFromUri = AuthorizationRequestURI.queryParam(data, "client_id")

        // Anything other than request_uri_method=post is the plain GET of RFC 9101.
        let walletNonce: String? = RequestUriMethod.isPost(data) ? RequestUriMethod.newWalletNonce() : nil
        let encryptionKey: ECPrivateKey? = walletNonce != nil ? RequestUriMethod.newEncryptionKey() : nil
        var urlRequest = URLRequest(url: url)
        if let walletNonce {
            urlRequest.httpMethod = "POST"
            urlRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            urlRequest.setValue(RequestUriMethod.requestObjectMediaType, forHTTPHeaderField: "Accept")
            urlRequest.httpBody = UIApplicationUtils.shared.getFormEncodedString(params: [
                RequestUriMethod.walletMetadataField: RequestUriMethod.walletMetadata(encryptionKey: encryptionKey),
                RequestUriMethod.walletNonceField: walletNonce
            ]).data(using: .utf8)
        } else {
            urlRequest.httpMethod = "GET"
        }

        let rawData: Data
        let response: URLResponse
        do {
            (rawData, response) = try await NetworkLogger.send(urlRequest, tag: "presentation-request", session: session)
        } catch {
            throw PresentationRequestError.fetchFailed(EUDIError(from: ErrorResponse(message: error.localizedDescription, code: nil)))
        }
        if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
            let error = ErrorHandler.processError(data: rawData, contentType: http.value(forHTTPHeaderField: "Content-Type"))
            throw PresentationRequestError.fetchFailed(error ?? EUDIError(message: "Unable to process request", code: nil))
        }

        // A verifier given our key may answer with an encrypted request object; open it here so
        // the rest of the handling sees the signed request JWT as usual.
        var body = String(data: rawData, encoding: .utf8) ?? ""
        if let encryptionKey, !body.isEmpty {
            guard let opened = RequestUriMethod.unwrapEncrypted(body, key: encryptionKey) else {
                throw PresentationRequestError.nonceMismatch
            }
            body = opened
        }
        body = body.trimmingCharacters(in: .whitespacesAndNewlines)
        if body.isEmpty { throw PresentationRequestError.emptyResponse }

        var request: PresentationRequest
        var isRequestObject = false
        if let json = parseJson(body) {
            // Not in OpenID4VP 1.0, which requires a request object (section 5.10.1). Kept for
            // the verifiers that answer with the bare parameters.
            debugPrint("RemotePresentationRequestSource: request_uri answered with plain JSON instead of a request object")
            request = json
        } else {
            request = try RequestObjectParser.parse(body)
            try RequestObjectParser.requireSignedUnlessRedirectUri(body, request, policy: policy)
            isRequestObject = true
        }
        // Section 5.10.1: a request object fetched by POST MUST carry the wallet_nonce it was
        // asked for; without it the request is dropped.
        if !RequestUriMethod.nonceAccepted(sent: walletNonce, received: request.walletNonce) {
            throw PresentationRequestError.nonceMismatch
        }
        try RequestObjectParser.requireMatchingClientId(clientIdFromUri, request)
        if isRequestObject {
            request = try await RequestObjectParser.verifyClient(request)
        }
        return request
    }

    private func parseJson(_ body: String) -> PresentationRequest? {
        guard body.hasPrefix("{") else { return nil }
        return try? JSONDecoder().decode(PresentationRequest.self, from: Data(body.utf8))
    }
}
