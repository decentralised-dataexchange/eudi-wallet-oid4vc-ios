//
//  DeferredRequestParameters.swift
//

import Foundation

/// The deferred credential request body, assembled once.
///
/// Section 9.1: `transaction_id` is REQUIRED, `credential_identifier` MAY be included. The draft
/// form has no body at all — it carries its handle in the Authorization header — which is why
/// ``DeferredTransaction/legacyAcceptanceToken(_:)`` produces an empty object here.
///
/// Mirrors `DeferredRequestParameters` in the Android SDK.
enum DeferredRequestParameters {

    static func build(
        transaction: DeferredTransaction,
        policy: DeferredRequestPolicy
    ) -> [String: Any] {
        switch transaction {
        case .legacyAcceptanceToken:
            return [:]

        case let .transactionId(value, credentialIdentifier):
            var out: [String: Any] = ["transaction_id": value]
            if policy.sendCredentialIdentifier,
               let credentialIdentifier, !credentialIdentifier.isEmpty {
                out["credential_identifier"] = credentialIdentifier
            }
            return out
        }
    }
}
