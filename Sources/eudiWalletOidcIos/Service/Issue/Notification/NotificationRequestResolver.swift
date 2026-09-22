//
//  NotificationRequestResolver.swift
//

import Foundation

/// Tells the issuer what happened to a credential it issued (section 11).
///
/// Mirrors `NotificationRequestResolver` in the Android SDK.
struct NotificationRequestResolver {

    func resolve(
        session: IssuanceSession,
        token: TokenResponse,
        notificationId: String,
        event: NotificationEvent,
        eventDescription: String? = nil,
        attestation: WalletAttestation? = nil,
        dpopNonce: String? = nil,
        urlSession: URLSession = URLSession(configuration: .default)
    ) async -> NotificationOutcome {

        guard let endpoint = session.issuerConfig?.notificationEndPoint, !endpoint.isEmpty else {
            // Section 11: the endpoint is optional, so its absence is not an error — but the caller
            // should know nothing was sent rather than assume it was.
            return .failed(error: EUDIError(message: "This issuer published no notification endpoint"))
        }
        guard !notificationId.isEmpty else {
            return .failed(error: EUDIError(message: "The credential response carried no notification_id"))
        }

        let parameters = NotificationRequestParameters.build(
            notificationId: notificationId, event: event, eventDescription: eventDescription
        )
        guard var request = HTTPCall.jsonPost(
            url: endpoint, body: parameters, attestation: attestation
        ) else {
            return .failed(error: EUDIError(message: "The notification request could not be built for \(endpoint)"))
        }

        let accessToken = token.accessToken ?? ""
        var dpop: String?
        if token.tokenType?.caseInsensitiveCompare("DPoP") == .orderedSame
            || attestation?.hasDPoPKey == true {
            dpop = attestation?.dpopProof(
                for: endpoint,
                nonce: dpopNonce,
                extraClaims: ["ath": DPoPProofService.computeAccessTokenHash(token: accessToken)]
            )
        }
        request.setValue(
            "\(dpop != nil ? "DPoP" : "Bearer") \(accessToken)",
            forHTTPHeaderField: "Authorization"
        )
        if let dpop { request.setValue(dpop, forHTTPHeaderField: "DPoP") }

        debugPrint("notification: endpoint=\(endpoint) event=\(event.rawValue) id=\(notificationId)")

        do {
            let result = try await HTTPCall.send(
                request,
                tag: "notification",
                session: urlSession,
                onTransportFailure: notificationTransportFailure
            )

            // Section 11.2: 204 No Content is the success. Anything else 2xx is accepted too —
            // some issuers answer 200 with an empty body.
            if result.isSuccessful {
                debugPrint("notification acknowledged (\(result.status))")
                return .acknowledged
            }

            let error = ErrorHandler.processError(
                data: result.data,
                contentType: result.contentType,
                httpStatus: result.status
            )
            debugPrint("notification refused \(result.status) error=\(error?.errorCode ?? "-")")
            return .failed(error: error ?? EUDIError(
                message: "The notification was refused (HTTP \(result.status))",
                httpStatus: result.status
            ))
        } catch {
            debugPrint("notification failed: \(error.localizedDescription)")
            return .failed(error: EUDIError(message: error.localizedDescription))
        }
    }
}

/// @see ``HTTPCall``
func notificationTransportFailure(_ detail: String?, _ failingURL: String?) -> Error {
    CredentialRequestError.requestFailed(detail ?? "The notification request failed")
}
