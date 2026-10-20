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
    ///   server authenticates clients that way, and the DPoP key the tokens are bound to. The
    ///   refresh token was issued to an attested client, so the refresh request carries the same
    ///   two headers, the same `client_id` and the same kind of DPoP proof the token request did.
    public func refresh(
        refreshToken: String,
        tokenEndpoint: String,
        attestation: WalletAttestation? = nil,
        urlSession: URLSession = URLSession(configuration: .default)
    ) async -> (String?, String?) {
        var parameters = [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
        ]
        // RFC 6749 section 3.2.1: a client that identified itself at the token endpoint does so on
        // the refresh too, with the same identifier -- the wallet unit's, read from the
        // attestation's `sub` as the Android SDK's `WalletUnitAttestationHeaders.clientId` does.
        if let jwt = attestation?.sanitisedAttestationJwt, let clientId = IssueService.wuaSub(jwt) {
            parameters["client_id"] = clientId
        }
        return await send(
            parameters: parameters,
            tokenEndpoint: tokenEndpoint,
            attestation: attestation,
            dpopNonce: nil,
            allowRetry: true,
            urlSession: urlSession
        )
    }

    private func send(
        parameters: [String: String],
        tokenEndpoint: String,
        attestation: WalletAttestation?,
        dpopNonce: String?,
        allowRetry: Bool,
        urlSession: URLSession
    ) async -> (String?, String?) {
        guard var request = HTTPCall.formPost(
            url: tokenEndpoint,
            parameters: parameters,
            attestation: attestation
        ) else { return (nil, nil) }

        // RFC 9449 section 5: a refresh token bound to a DPoP key is presented with a proof for the
        // same key. A token-endpoint proof: `htm` and `htu` only, no `ath`.
        if let dpop = attestation?.dpopProof(for: tokenEndpoint, nonce: dpopNonce) {
            request.setValue(dpop, forHTTPHeaderField: "DPoP")
        }

        do {
            let result = try await HTTPCall.send(
                request,
                tag: "token-refresh",
                session: urlSession,
                onTransportFailure: { detail, _ in
                    CredentialRequestError.requestFailed(detail ?? "The token refresh failed")
                }
            )
            if result.isSuccessful {
                let json = (try? JSONSerialization.jsonObject(with: result.data)) as? [String: Any]
                return (json?["access_token"] as? String, json?["refresh_token"] as? String)
            }

            // RFC 9449 section 8: the server may answer with a nonce it wants in the proof. Once.
            if allowRetry, attestation?.hasDPoPKey == true,
               let nonce = result.header("DPoP-Nonce"), !nonce.isEmpty {
                debugPrint("token endpoint asked for a DPoP nonce on refresh; retrying once")
                return await send(
                    parameters: parameters,
                    tokenEndpoint: tokenEndpoint,
                    attestation: attestation,
                    dpopNonce: nonce,
                    allowRetry: false,
                    urlSession: urlSession
                )
            }

            let error = ErrorHandler.processError(
                data: result.data, contentType: result.contentType, httpStatus: result.status
            )
            debugPrint("token refresh refused \(result.status) error=\(error?.errorCode ?? "-")")
            return (nil, nil)
        } catch {
            debugPrint("token refresh failed: \(error.localizedDescription)")
            return (nil, nil)
        }
    }
}
