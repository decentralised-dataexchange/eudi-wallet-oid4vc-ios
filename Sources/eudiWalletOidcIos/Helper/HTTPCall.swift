//
//  HTTPCall.swift
//
//  Performing a request, keeping the status code and the headers.
//

import Foundation

/// Performs a request, keeping the status and the headers.
///
/// Mirrors `AuthorizationHttp` in the Android SDK, where the equivalent helper exists because the
/// shared `SafeApiCall` discarded the status code -- which meant a "PAR rejected" diagnostic
/// written for a 400 could only ever fire for a 3xx.
enum HTTPCall {

    struct Result {
        let data: Data
        let status: Int
        let headers: [AnyHashable: Any]

        func header(_ name: String) -> String? {
            (headers.first { ($0.key as? String)?.caseInsensitiveCompare(name) == .orderedSame })?
                .value as? String
        }

        var contentType: String? { header("Content-Type") }
        var isSuccessful: Bool { (200..<300).contains(status) }
    }

    /// - Throws: ``AuthorizationError/requestFailed(detail:failingURL:)`` when the request never
    ///   completed. The failing URL is carried through because a custom-scheme redirect surfaces as
    ///   a load failure whose failing URL is the callback.
    /// - Parameter onTransportFailure: builds the error thrown when the request never completed,
    ///   so each leg raises its own type. The failing URL matters: a redirect to a custom scheme
    ///   cannot be loaded, and the URL it failed on *is* the callback.
    static func send(
        _ request: URLRequest,
        tag: String,
        session: URLSession,
        onTransportFailure: (String?, String?) -> Error
    ) async throws -> Result {
        do {
            let (data, response) = try await NetworkLogger.send(request, tag: tag, session: session)
            let http = response as? HTTPURLResponse
            return Result(
                data: data,
                status: http?.statusCode ?? 0,
                headers: http?.allHeaderFields ?? [:]
            )
        } catch {
            let nsError = error as NSError
            let failingURL = (nsError.userInfo[NSURLErrorFailingURLStringErrorKey] as? String)
                ?? (nsError.userInfo[NSURLErrorFailingURLErrorKey] as? URL)?.absoluteString
            throw onTransportFailure(nsError.localizedDescription, failingURL)
        }
    }

    /// A form-encoded POST carrying the wallet attestation headers when there are any.
    static func formPost(
        url: String,
        parameters: [String: String],
        attestation: WalletAttestation?
    ) -> URLRequest? {
        guard let endpoint = URL(string: url) else { return nil }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = UIApplicationUtils.shared
            .getFormEncodedString(params: parameters)
            .data(using: .utf8)
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        // Deliberately not logged: the attestation and its proof are credentials in their own right.
        if let jwt = attestation?.sanitisedAttestationJwt {
            request.setValue(jwt, forHTTPHeaderField: "OAuth-Client-Attestation")
            request.setValue(attestation?.proofOfPossession ?? "", forHTTPHeaderField: "OAuth-Client-Attestation-PoP")
        }
        return request
    }

    /// A JSON POST carrying the wallet attestation headers when there are any.
    ///
    /// The credential request is JSON (or JWT when encrypted), not form-encoded, so it cannot use
    /// ``formPost(url:parameters:attestation:)`` -- but the attestation headers are the same, and
    /// so is the reason they are not logged.
    ///
    /// - Returns: `nil` when the URL is unusable or the body is not a serialisable JSON object.
    ///   `JSONSerialization` raises an **Objective-C** exception on an invalid top-level object,
    ///   which a Swift `do`/`catch` cannot catch, so `isValidJSONObject` is checked first.
    static func jsonPost(
        url: String,
        body: [String: Any],
        attestation: WalletAttestation?
    ) -> URLRequest? {
        guard JSONSerialization.isValidJSONObject(body),
              let data = try? JSONSerialization.data(withJSONObject: body) else { return nil }
        return post(url: url, body: data, contentType: "application/json", attestation: attestation)
    }

    /// A POST whose body is a compact-serialised JWE, section 10's encrypted credential request.
    static func jwtPost(
        url: String,
        body: String,
        attestation: WalletAttestation?
    ) -> URLRequest? {
        post(url: url, body: Data(body.utf8), contentType: "application/jwt", attestation: attestation)
    }

    private static func post(
        url: String,
        body: Data,
        contentType: String,
        attestation: WalletAttestation?
    ) -> URLRequest? {
        guard let endpoint = URL(string: url) else { return nil }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        // Deliberately not logged: the attestation and its proof are credentials in their own right.
        if let jwt = attestation?.sanitisedAttestationJwt {
            request.setValue(jwt, forHTTPHeaderField: "OAuth-Client-Attestation")
            request.setValue(attestation?.proofOfPossession ?? "", forHTTPHeaderField: "OAuth-Client-Attestation-PoP")
        }
        return request
    }
}
