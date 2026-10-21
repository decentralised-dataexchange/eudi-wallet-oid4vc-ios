//
//  ClientIdentifierVerifier.swift
//  eudiWalletOidcIos
//

import Foundation

/// Picks the handler for the request's client identifier prefix and runs it (OpenID4VP 1.0
/// section 5.9). Called once per request from the resolver, after the parameters are complete.
///
/// Under `ClientVerification.enforced` a broken rule refuses the request. Under
/// `ClientVerification.audit` the same checks run, and a failure is logged and reported in the
/// returned `VerifierIdentity` instead.
struct ClientIdentifierVerifier {

    let handlers: [ClientIdentifierHandler]

    init(handlers: [ClientIdentifierHandler] = Self.defaultHandlers()) {
        self.handlers = handlers
    }

    func verify(_ request: inout PresentationRequest, policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        let clientId = request.clientId?.trimmingCharacters(in: .whitespacesAndNewlines)
        let present = clientId?.isEmpty == false ? clientId : nil
        let parsed = ClientIdentifier.parse(present ?? "", legacyScheme: request.clientIDScheme)

        if policy.clientVerification == .off {
            return VerifierIdentity(identifier: parsed, verified: false, reason: "client verification is off")
        }
        do {
            return try await check(present, parsed, &request, policy)
        } catch let error as PresentationRequestError {
            if policy.clientVerification == .enforced { throw error }
            debugPrint("ClientIdentifierVerifier: client identity not verified (audit): \(error.message)")
            return VerifierIdentity(identifier: parsed, verified: false, reason: error.message)
        }
    }

    private func check(_ clientId: String?, _ identifier: ClientIdentifier, _ request: inout PresentationRequest,
                       _ policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        if clientId == nil {
            throw PresentationRequestError.clientNotVerified("the request carries no client_id")
        }
        if identifier.prefix == .origin {
            // Section 5.9.3: "The Wallet MUST NOT accept this Client Identifier Prefix in requests."
            throw PresentationRequestError.clientNotVerified("the origin prefix is reserved for the Digital Credentials API")
        }
        guard let handler = handlers.first(where: { $0.prefixes.contains(identifier.prefix) }) else {
            throw PresentationRequestError.unsupportedClientIdPrefix(identifier.prefix.value ?? "")
        }
        let identity = try await handler.verify(&request, identifier, policy: policy)
        if policy.requireAnchoredClients && identity.verified && !identity.anchored {
            throw PresentationRequestError.clientNotVerified(
                identity.reason ?? "the verifier's key does not chain to a configured trust anchor")
        }
        debugPrint("ClientIdentifierVerifier: client \(identifier.original): verified=\(identity.verified) anchored=\(identity.anchored)\(identity.reason.map { " (\($0))" } ?? "")")
        return identity
    }

    /// The values for `wallet_metadata.client_id_prefixes_supported` (section 5.10): the 1.0
    /// prefixes this registry can verify under `policy`. Derived here so the advertisement and the
    /// enforcement cannot drift apart.
    func supportedPrefixes(_ policy: PresentationRequestPolicy) -> [String] {
        var seen = Set<String>()
        return handlers.filter { $0.supported(policy) }
            .flatMap { handler in ClientIdPrefix.allCases.filter { handler.prefixes.contains($0) } }
            .filter { !$0.isLegacy && $0 != .preRegistered && $0 != .origin }
            .compactMap { $0.value }
            .filter { seen.insert($0).inserted }
    }

    /// Ordered: 1.0 prefixes first, legacy last.
    static func defaultHandlers() -> [ClientIdentifierHandler] {
        [
            RedirectUriClientHandler(),
            X509SanDnsClientHandler(),
            X509HashClientHandler(),
            DecentralizedIdentifierClientHandler(),
            VerifierAttestationClientHandler(),
            OpenIdFederationClientHandler(),
            // --- legacy, safe to delete as a block ---
            PreRegisteredClientHandler(),
            WebOriginClientHandler(),
            X509SanUriClientHandler(),
        ]
    }
}
