//
//  File.swift
//
//
//  Created by iGrant on 28/02/25.
//
import Foundation
import CryptoKit

public class NotificationService {
    public init() {}

    /// Tells the issuer what happened to a credential (section 11).
    ///
    /// Returns a ``NotificationOutcome`` rather than nothing: `sendNoticationStatus` decoded a
    /// failure into a local it then discarded, so a caller could not tell an acknowledged
    /// notification from one the issuer refused — section 11.2's 204 from a 400 naming
    /// `invalid_notification_id`.
    public func notify(
        session: IssuanceSession,
        token: TokenResponse,
        notificationId: String,
        event: NotificationEvent,
        eventDescription: String? = nil,
        attestation: WalletAttestation? = nil,
        dpopNonce: String? = nil
    ) async -> NotificationOutcome {
        await NotificationRequestResolver().resolve(
            session: session,
            token: token,
            notificationId: notificationId,
            event: event,
            eventDescription: eventDescription,
            attestation: attestation,
            dpopNonce: dpopNonce
        )
    }

    @available(*, deprecated, message: "Returns Void, so an acknowledged notification and a refused one are indistinguishable. Use notify(session:token:notificationId:event:), which returns a NotificationOutcome.")
    
    public func sendNoticationStatus(endPoint: String?, event: String?, notificationID: String?, accessToken: String, refreshToken: String, tokenEndPoint: String, isDPOPSupported: Bool = false, dpopKey: P256.Signing.PrivateKey? = nil, dpopKeyHandler: SecureKeyProtocol? = nil, dpopKeyPublicJwk: [String: Any]? = nil) async {
        guard let url = URL(string: endPoint ?? "") else { return }
        var request = URLRequest(url: url)
        var params: [String: Any] = [:]
        params = ["notification_id": notificationID ?? "", "event": event ?? ""]
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue( "Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        let requestBodyData = try? JSONSerialization.data(withJSONObject: params)
        request.httpBody =  requestBodyData
        let athClaims: [String: Any] = ["ath": DPoPProofService.computeAccessTokenHash(token: accessToken)]
        let dpopProof: String?
        if let dpopHandler = dpopKeyHandler, let dpopJwk = dpopKeyPublicJwk {
            dpopProof = DPoPProofService.generateProof(tokenEndpoint: endPoint ?? "", keyHandler: dpopHandler, publicJwk: dpopJwk, claims: athClaims)
        } else {
            dpopProof = DPoPProofService.generateProof(tokenEndpoint: endPoint ?? "", dpopKey: dpopKey, claims: athClaims)
        }
        
        if isDPOPSupported {
            request.setValue(dpopProof, forHTTPHeaderField: "DPoP")
        }
        
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let httpRes = response as? HTTPURLResponse
            if httpRes?.statusCode ?? 0 >= 400 {
                let errorString = String(data: data, encoding: .utf8)
                let error = EUDIError(from: ErrorResponse(message: errorString))
            } else if httpRes?.statusCode == 204 {
                print("success")
            }
        } catch {
            let nsError = error as NSError
            let errorCode = nsError.code
            let error = EUDIError(from: ErrorResponse(message:error.localizedDescription, code: errorCode))
        }
    }
    
    @available(*, deprecated, message: "Token refresh moved to TokenRefreshService, mirroring services/tokenRefresh/ in the Android SDK. Use TokenRefreshService().refresh(refreshToken:tokenEndpoint:attestation:).")
    public func refreshAccessToken(refreshToken: String, endPoint: String, wua: String = "", pop: String = "") async -> (String?, String?) {
        await TokenRefreshService().refresh(
            refreshToken: refreshToken,
            tokenEndpoint: endPoint,
            attestation: wua.isEmpty ? nil : WalletAttestation(attestationJwt: wua, proofOfPossession: pop)
        )
    }
    
}

