//
//  TrustMechanismProvider.swift
//  eudiWalletOidcIos
//
//  Single pick-point for the trust mechanism implementation — the Swift analog of the Android SDK's
//  `TrustEvaluator.trustMechanism()`.
//

import Foundation

/// The trust mechanism used to decide whether an issuer/verifier is trusted.
///
/// The SDK ships two interchangeable implementations of `TrustMechanismServiceProtocol`; change
/// `shared` to switch the trust source everywhere trust is evaluated:
///
///  - `ServerTrustMechanismService.shared` (default) — queries the OWS Trust List backend
///    (POST {baseURL}/trust-list/lookup). Open endpoint, no auth. Set the base URL via
///    `ServerTrustMechanismService.configure(baseURL:)`.
///  - `TrustMechanismService.shared` — matches against the local/static EU TSL XML trust list.
///
/// To use the local trust list instead of the server, set:
///     TrustMechanismProvider.shared = TrustMechanismService.shared
///
/// To plug in a custom trust source, conform to `TrustMechanismServiceProtocol` and assign it here —
/// the rest of the trust flow (e.g. `FilterCredentialService`) is implementation-agnostic.
enum TrustMechanismProvider {
    static var shared: TrustMechanismServiceProtocol = ServerTrustMechanismService.shared
}
