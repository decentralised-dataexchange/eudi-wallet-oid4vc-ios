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
    /// - Parameter attestation: the wallet unit attestation to present, when the authorization
    ///   server authenticates clients that way. The refresh token was issued to an attested
    ///   client, so the refresh request carries the same two headers the token request did.
    public func refresh(
        refreshToken: String,
        tokenEndpoint: String,
        attestation: WalletAttestation? = nil,
        urlSession: URLSession = URLSession(configuration: .default)
    ) async -> (String?, String?) {
        guard let request = HTTPCall.formPost(
            url: tokenEndpoint,
            parameters: [
                "grant_type": "refresh_token",
                "refresh_token": refreshToken,
            ],
            attestation: attestation
        ) else { return (nil, nil) }

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
