//
//  TokenRefreshService.swift
//

import Foundation

/// Exchanges a refresh token for a new access token (RFC 6749 section 6).
///
/// Moved out of `NotificationService`, where it had no business being: token refresh is a
/// token-endpoint concern, and its presence there is the only reason 12 wallet view models pass a
/// `refreshToken` and a `tokenEndPoint` in order to *send a notification*.
///
/// Mirrors `services/tokenRefresh/TokenRefreshService` in the Android SDK, which has always kept it
/// in its own folder.
public class TokenRefreshService {

    public init() {}

    /// - Returns: the new access token and refresh token, or `(nil, nil)` when the refresh failed.
    ///   The tuple shape is what the previous implementation returned and what its callers read.
    public func refresh(
        refreshToken: String,
        tokenEndpoint: String,
        urlSession: URLSession = URLSession(configuration: .default)
    ) async -> (String?, String?) {
        guard let url = URL(string: tokenEndpoint) else { return (nil, nil) }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = UIApplicationUtils.shared.getFormEncodedString(params: [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
        ]).data(using: .utf8)

        do {
            let result = try await HTTPCall.send(
                request,
                tag: "token-refresh",
                session: urlSession,
                onTransportFailure: { detail, _ in
                    CredentialRequestError.requestFailed(detail ?? "The token refresh failed")
                }
            )
            guard result.isSuccessful else {
                let error = ErrorHandler.processError(
                    data: result.data, contentType: result.contentType, httpStatus: result.status
                )
                debugPrint("token refresh refused \(result.status) error=\(error?.errorCode ?? "-")")
                return (nil, nil)
            }
            let json = (try? JSONSerialization.jsonObject(with: result.data)) as? [String: Any]
            return (json?["access_token"] as? String, json?["refresh_token"] as? String)
        } catch {
            debugPrint("token refresh failed: \(error.localizedDescription)")
            return (nil, nil)
        }
    }
}
