//
//  NetworkLogger.swift
//
//  Request/response tracing for every HTTP call the SDK makes. Every line is
//  prefixed with `[EUDI-NET]` so the whole trace can be filtered in the console.
//
//  The default level mirrors the Android SDK's Logger: bodies in debug builds,
//  headers only in release. Bodies carry credentials, access tokens and the
//  wallet unit attestation, so they are never printed in a shipped build.
//

import Foundation

public enum NetworkLogger {

    /// Master switch. Set to `false` to silence all tracing.
    public static var isEnabled: Bool = true

    /// Whether request/response bodies are printed. Debug-only by default -
    /// a body can contain a credential or a bearer token.
    #if DEBUG
    public static var logsBodies: Bool = true
    #else
    public static var logsBodies: Bool = false
    #endif

    /// Bodies longer than this are truncated (character count).
    public static var maxBodyLength: Int = 8192

    private static let prefix = "[EUDI-NET]"

    // MARK: - Wrapped calls

    /// `URLSession.data(for:)` with the request, status, timing and body traced.
    public static func send(_ request: URLRequest,
                            tag: String,
                            session: URLSession = .shared) async throws -> (Data, URLResponse) {
        logRequest(tag, request)
        let start = Date()
        do {
            let (data, response) = try await session.data(for: request)
            logResponse(tag, request, data: data, response: response, error: nil, started: start)
            return (data, response)
        } catch {
            logResponse(tag, request, data: nil, response: nil, error: error, started: start)
            throw error
        }
    }

    /// `URLSession.data(from:)` with tracing.
    public static func send(url: URL,
                            tag: String,
                            session: URLSession = .shared) async throws -> (Data, URLResponse) {
        try await send(URLRequest(url: url), tag: tag, session: session)
    }

    // MARK: - Manual logging (completion-handler call sites)

    public static func logRequest(_ tag: String, _ request: URLRequest) {
        guard isEnabled else { return }
        let method = request.httpMethod ?? "GET"
        print("\(prefix) → \(tag) \(method) \(request.url?.absoluteString ?? "<nil url>")")
        for (key, value) in request.allHTTPHeaderFields ?? [:] {
            print("\(prefix)     header \(key): \(redacted(key, value))")
        }
        if logsBodies, let body = request.httpBody, !body.isEmpty {
            print("\(prefix)     body \(bodyString(body))")
        }
    }

    public static func logResponse(_ tag: String,
                                   _ request: URLRequest,
                                   data: Data?,
                                   response: URLResponse?,
                                   error: Error?,
                                   started: Date? = nil) {
        guard isEnabled else { return }
        let url = request.url?.absoluteString ?? "<nil url>"
        let ms = started.map { String(format: " %.0fms", Date().timeIntervalSince($0) * 1000) } ?? ""
        if let error = error {
            let nsError = error as NSError
            print("\(prefix) ✗ \(tag) FAILED\(ms) \(url)")
            print("\(prefix)     error \(nsError.domain) \(nsError.code): \(nsError.localizedDescription)")
            return
        }
        let http = response as? HTTPURLResponse
        let status = http.map { String($0.statusCode) } ?? "no-http-response"
        let marker = (http?.statusCode ?? 0) >= 400 ? "✗" : "←"
        print("\(prefix) \(marker) \(tag) \(status)\(ms) \(url)")
        if let http = http {
            for (key, value) in http.allHeaderFields {
                print("\(prefix)     header \(key): \(redacted("\(key)", "\(value)"))")
            }
        }
        if logsBodies, let data = data, !data.isEmpty {
            print("\(prefix)     body \(bodyString(data))")
        }
    }

    // MARK: - Helpers

    /// Credential-bearing headers are shown in full only in debug builds; a
    /// release trace keeps the header name and a length, never the value.
    private static func redacted(_ key: String, _ value: String) -> String {
        #if DEBUG
        return value
        #else
        let sensitive = ["authorization", "oauth-client-attestation",
                         "oauth-client-attestation-pop", "dpop", "set-cookie", "cookie"]
        guard sensitive.contains(key.lowercased()) else { return value }
        return "<redacted, \(value.count) chars>"
        #endif
    }

    private static func bodyString(_ data: Data) -> String {
        guard let text = String(data: data, encoding: .utf8) else {
            return "<\(data.count) bytes, not utf8>"
        }
        guard text.count > maxBodyLength else { return text }
        return String(text.prefix(maxBodyLength)) + "… <truncated, \(text.count) chars>"
    }
}
