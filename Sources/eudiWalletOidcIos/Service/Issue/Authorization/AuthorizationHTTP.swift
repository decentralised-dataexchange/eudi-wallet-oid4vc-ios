//
//  AuthorizationHTTP.swift
//
//  Performing an authorization-leg request, keeping the response.
//

import Foundation

/// Performs an authorization-leg request, keeping the status and the headers.
///
/// Mirrors `AuthorizationHttp` in the Android SDK, where the equivalent helper exists because the
/// shared `SafeApiCall` discarded the status code -- which meant a "PAR rejected" diagnostic
/// written for a 400 could only ever fire for a 3xx.
enum AuthorizationHTTP {

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
    static func send(
        _ request: URLRequest,
        tag: String,
        session: URLSession
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
            throw AuthorizationError.requestFailed(
                detail: nsError.localizedDescription,
                failingURL: failingURL
            )
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
}
