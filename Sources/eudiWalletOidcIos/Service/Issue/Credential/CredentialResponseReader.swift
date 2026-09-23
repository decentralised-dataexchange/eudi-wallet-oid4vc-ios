//
//  CredentialResponseReader.swift
//

import Foundation

/// Reads a 2xx credential response into a ``CredentialOutcome``.
///
/// Extracted from ``CredentialRequestResolver`` because section 9.2 makes the **Deferred** Credential
/// Response the same shape as the Credential Response — "the Deferred Credential Response ... MAY
/// itself be deferred again" — so the credential leg and the deferred leg read the same body, and
/// re-issuance reaches it through the credential leg. Three copies of this is how the plural
/// `credentials` array came to be honoured in one place and dropped in the others.
///
/// Sections 8.3 and 9.2. Mirrors `CredentialResponseReader` in the Android SDK.
enum CredentialResponseReader {

    /// - Parameter fallbackTransactionId: the handle the caller is already polling with, reused
    ///   when a non-conformant issuer defers without naming one — see the `interval` branch below.
    ///   Only the deferred leg passes it, and only when its policy allows: on a first credential
    ///   request there is no prior handle, so there is nothing to fall back to.
    /// - Throws: ``CredentialRequestError/unusable(_:status:)`` when the body cannot be read at all.
    static func read(
        _ result: HTTPCall.Result,
        encryption: CredentialEncryption,
        fallbackTransactionId: String? = nil
    ) throws -> CredentialOutcome {
        guard !result.data.isEmpty else {
            throw CredentialRequestError.unusable("The issuer returned an empty credential response")
        }

        var data = result.data
        // `contains`, not `==`: the exact compare this replaces missed
        // `application/jwt; charset=utf-8`.
        if result.contentType?.localizedCaseInsensitiveContains("application/jwt") == true {
            guard let jwe = String(data: result.data, encoding: .utf8) else {
                throw CredentialRequestError.unusable("The encrypted credential response is not text")
            }
            guard let responseKey = encryption.responseKey else {
                throw CredentialRequestError.unusable(
                    "The issuer encrypted the response but no decryption key was supplied"
                )
            }
            guard let decrypted = JWEDecryptor().decrypt(jwe, privateKey: responseKey) else {
                throw CredentialRequestError.unusable(
                    "The encrypted credential response could not be decrypted"
                )
            }
            data = Data(decrypted.utf8)
        }

        guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw CredentialRequestError.unusable("The credential response is not valid JSON")
        }

        // Draft issuers call the deferred handle `acceptance_token`; 1.0 calls it `transaction_id`.
        // Section 9.2: a deferred response may carry one again, so this is reached on both legs.
        let transactionId = (json["transaction_id"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            ?? (json["acceptance_token"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        if let transactionId {
            return .deferred(transactionId: transactionId, interval: json["interval"] as? Double)
        }

        // Section 8.3's `credentials` is an array. The previous implementation surfaced only the
        // first, and the wallet then read index 0 of that.
        var credentials = (json["credentials"] as? [[String: Any]] ?? [])
            .compactMap { $0["credential"] as? String }
        if credentials.isEmpty, let single = json["credential"] as? String, !single.isEmpty {
            credentials = [single]
        }
        guard !credentials.isEmpty else {
            // A shape 1.0 does not define. Section 9.3 signals a pending credential with 400 and
            // `issuance_pending`; section 9.2 makes `transaction_id` REQUIRED in a 200 that defers
            // again, and `interval` is not a member of the success response at all. An issuer met
            // in the field sends 200 with `interval` and nothing else, so read strictly this is
            // "neither a credential nor a transaction id" and polling stops on a credential that
            // is still coming.
            //
            // The caller decides whether to accept it -- DeferredRequestPolicy.acceptIntervalOnlyAsPending
            // withholds the fallback when it should not be. The `interval` still gates it here:
            // it is the only positive evidence the response means "come back later" rather than
            // "something went wrong".
            if let interval = json["interval"] as? Double, let fallbackTransactionId {
                return .deferred(transactionId: fallbackTransactionId, interval: interval)
            }
            throw CredentialRequestError.unusable(
                "The issuer returned neither a credential nor a transaction id"
            )
        }

        return .issued(
            credentials: credentials,
            notificationId: json["notification_id"] as? String,
            cNonce: json["c_nonce"] as? String
        )
    }
}
