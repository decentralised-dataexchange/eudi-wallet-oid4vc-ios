//
//  DirectPostClient.swift
//  eudiWalletOidcIos
//

import Foundation

/// OpenID4VP 1.0 section 8.2: the Authorization Response goes to the `response_uri` as an
/// `application/x-www-form-urlencoded` POST, and a verifier that processed it "MUST respond with an
/// HTTP status code of 200 with Content-Type of application/json and a JSON object in the response
/// body", optionally carrying `redirect_uri`. A 204 is taken as acceptance without a redirect, and a
/// 3xx `Location` is read for the verifiers that answer with one, so redirects are not followed.
struct DirectPostClient {

    /// A session that hands redirects back instead of following them. Replaceable in tests.
    static var session = URLSession(configuration: .default, delegate: RedirectRefusal(), delegateQueue: nil)

    var session: URLSession = DirectPostClient.session

    func post(_ responseUri: String, fields: [String: String], headers: [String: String]) async -> PresentationOutcome {
        guard let url = URL(string: responseUri) else {
            return .refused(EUDIError(message: SubmissionError.noResponseUri.errorDescription, errorCode: "invalid_request"))
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        headers.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }
        request.httpBody = Data(UIApplicationUtils.shared.getFormEncodedString(params: fields).utf8)

        let data: Data
        let response: HTTPURLResponse?
        do {
            let (body, answer) = try await NetworkLogger.send(request, tag: "vp-token-response", session: session)
            data = body
            response = answer as? HTTPURLResponse
        } catch {
            return .refused(EUDIError(message: error.localizedDescription))
        }

        let status = response?.statusCode ?? 0
        switch status {
        case 200:
            let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            func field(_ name: String) -> String? { (json?[name] as? String).flatMap { $0.isEmpty ? nil : $0 } }
            // `code` is what an issuer's interactive authorization endpoint answers a presentation
            // with; a verifier's response URI sends `redirect_uri`.
            return .accepted(redirectUri: field("redirect_uri"), location: nil, authorizationCode: field("code"))
        case 204:
            return .accepted(redirectUri: nil, location: nil, authorizationCode: nil)
        case 300..<400:
            let location = response?.value(forHTTPHeaderField: "Location")
            if let location, var error = Self.error(in: location) {
                error.httpStatus = status
                return .refused(error)
            }
            return .accepted(redirectUri: nil, location: location, authorizationCode: nil)
        default:
            var error = ErrorHandler.processError(data: data, contentType: response?.value(forHTTPHeaderField: "Content-Type"),
                                                  httpStatus: status) ?? EUDIError(message: nil, httpStatus: status)
            if error.message?.isEmpty ?? true { error.message = "The verifier did not accept the presentation" }
            return .refused(error)
        }
    }

    /// The OAuth error carried in a redirect's query or fragment, when there is one.
    static func error(in location: String) -> EUDIError? {
        let afterQuery = location.split(separator: "?", maxSplits: 1).dropFirst().first.map(String.init)
        let query = afterQuery?.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init)
            ?? location.split(separator: "#", maxSplits: 1).dropFirst().first.map(String.init) ?? ""
        var params: [String: String] = [:]
        for pair in query.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let key = parts.first, !key.isEmpty else { continue }
            let raw = parts.count > 1 ? String(parts[1]) : ""
            params[String(key)] = raw.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? raw
        }
        guard let code = params["error"] else { return nil }
        return EUDIError(message: params["error_description"] ?? code, errorCode: code, errorUri: params["error_uri"])
    }
}

/// Stops the redirection and returns the 3xx answer itself.
final class RedirectRefusal: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
