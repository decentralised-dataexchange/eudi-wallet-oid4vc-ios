//
//  DeferredRequestResolver.swift
//

import Foundation

/// Asks the issuer for a credential it deferred: send the handle, read the answer.
///
/// Returns the same ``CredentialOutcome`` as the credential request, because section 9.2 says the
/// Deferred Credential Response *is* the Credential Response — and "MAY itself be deferred again",
/// which arrives here as ``CredentialOutcome/deferred(transactionId:interval:)`` coming back out.
///
/// What this can do that the function it replaces could not, all downstream of ``HTTPCall``
/// replacing the bare transport:
///
///  - tell `issuance_pending` from `invalid_transaction_id`. Both used to be a bare `nil`, so a
///    wallet polled a permanently dead transaction until the credential's own expiry;
///  - report the issuer's `interval` (section 9.3: "the minimum number of seconds the Wallet MUST
///    wait"), instead of the caller guessing one;
///  - answer RFC 9449's DPoP nonce challenge.
///
/// Mirrors `DeferredRequestResolver` in the Android SDK.
struct DeferredRequestResolver {

    let policy: DeferredRequestPolicy

    init(policy: DeferredRequestPolicy = .standard) {
        self.policy = policy
    }

    func resolve(
        session: IssuanceSession,
        token: TokenResponse,
        transaction: DeferredTransaction,
        attestation: WalletAttestation? = nil,
        encryption: CredentialEncryption? = nil,
        dpopNonce: String? = nil,
        urlSession: URLSession = URLSession(configuration: .default)
    ) async -> CredentialOutcome {

        guard let endpoint = session.issuerConfig?.deferredCredentialEndpoint, !endpoint.isEmpty else {
            return .failed(error: CredentialRequestError.unusable(
                "This issuer deferred a credential but published no deferred credential endpoint"
            ).asEUDIError)
        }

        let resolvedEncryption = (encryption ?? CredentialEncryption()).resolved(against: session)

        do {
            return try await send(
                endpoint: endpoint,
                token: token,
                transaction: transaction,
                attestation: attestation,
                encryption: resolvedEncryption,
                dpopNonce: dpopNonce ?? token.dpopNonce,
                allowRetry: true,
                urlSession: urlSession
            )
        } catch let error as CredentialRequestError {
            debugPrint("deferred credential request failed: \(error.asEUDIError.message ?? "")")
            return .failed(error: error.asEUDIError)
        } catch {
            return .failed(error: EUDIError(message: error.localizedDescription))
        }
    }

    private func send(
        endpoint: String,
        token: TokenResponse,
        transaction: DeferredTransaction,
        attestation: WalletAttestation?,
        encryption: CredentialEncryption,
        dpopNonce: String?,
        allowRetry: Bool,
        urlSession: URLSession
    ) async throws -> CredentialOutcome {

        let parameters = DeferredRequestParameters.build(transaction: transaction, policy: policy)

        // The draft form authenticates with the handle itself and sends nothing; 1.0 uses the
        // access token from the credential request and names the transaction in the body.
        let accessToken: String
        var wantsDPoP = false
        switch transaction {
        case let .legacyAcceptanceToken(handle):
            accessToken = handle
        case .transactionId:
            accessToken = token.accessToken ?? ""
            wantsDPoP = token.tokenType?.caseInsensitiveCompare("DPoP") == .orderedSame
                || attestation?.hasDPoPKey == true
        }

        var request = try await buildRequest(
            endpoint: endpoint,
            parameters: parameters,
            encryption: encryption,
            attestation: attestation
        )

        var dpop: String?
        if wantsDPoP {
            // RFC 9449 section 4.2: the deferred endpoint is a resource server too.
            dpop = attestation?.dpopProof(
                for: endpoint,
                nonce: dpopNonce,
                extraClaims: ["ath": DPoPProofService.computeAccessTokenHash(token: accessToken)]
            )
            guard dpop != nil else {
                throw CredentialRequestError.unusable(
                    "This token is DPoP-bound but no DPoP proof could be produced"
                )
            }
        }
        request.setValue(
            "\(dpop != nil ? "DPoP" : "Bearer") \(accessToken)",
            forHTTPHeaderField: "Authorization"
        )
        if let dpop { request.setValue(dpop, forHTTPHeaderField: "DPoP") }

        let result = try await HTTPCall.send(
            request,
            tag: "deferred-credential-request",
            session: urlSession,
            onTransportFailure: credentialTransportFailure
        )

        if result.isSuccessful {
            return try CredentialResponseReader.read(result, encryption: encryption)
        }

        let error = ErrorHandler.processError(
            data: result.data,
            contentType: result.contentType,
            httpStatus: result.status
        )
        let issuedDPoPNonce = result.header("DPoP-Nonce")

        if allowRetry, policy.retryOnDPoPNonce, attestation?.hasDPoPKey == true,
           result.status == 400, error?.errorCode == Self.useDPoPNonce,
           let issuedDPoPNonce, !issuedDPoPNonce.isEmpty {
            debugPrint("deferred endpoint asked for a DPoP nonce; retrying once")
            return try await send(
                endpoint: endpoint, token: token, transaction: transaction,
                attestation: attestation, encryption: encryption,
                dpopNonce: issuedDPoPNonce, allowRetry: false, urlSession: urlSession
            )
        }

        // Section 9.3: the credential is not ready, and this is not a failure. Reporting it as one
        // is what made a wallet stop polling a transaction that was still coming.
        if error?.errorCode == Self.issuancePending {
            let retryAfter = pendingInterval(from: result.data)
            debugPrint("issuance still pending; the issuer asks for \(retryAfter?.description ?? "no") seconds")
            return .deferred(transactionId: transaction.value, interval: retryAfter)
        }

        debugPrint("deferred endpoint \(result.status) error=\(error?.errorCode ?? error?.message ?? "-")")
        return .failed(error: error ?? CredentialRequestError.rejected(
            status: result.status, body: result.data, contentType: result.contentType
        ).asEUDIError)
    }

    private func buildRequest(
        endpoint: String,
        parameters: [String: Any],
        encryption: CredentialEncryption,
        attestation: WalletAttestation?
    ) async throws -> URLRequest {
        // Section 10: the client "MUST" encrypt when the issuer sets `encryption_required`. The
        // draft form has no body to encrypt.
        guard encryption.requestEncryptionRequired, !parameters.isEmpty else {
            guard let request = HTTPCall.jsonPost(
                url: endpoint, body: parameters, attestation: attestation
            ) else {
                throw CredentialRequestError.unusable(
                    "The deferred credential request could not be built for \(endpoint)"
                )
            }
            return request
        }

        guard let jwk = encryption.request?.jwks?.first?.dictionary else {
            throw CredentialRequestError.unusable(
                "This issuer requires an encrypted deferred request but published no key"
            )
        }
        let encrypted: String
        do {
            encrypted = try await JWEEncryptor().encrypt(
                payload: parameters,
                jwks: jwk,
                supportedEncryptions: [CredentialRequestParameters.contentEncryption]
            )
        } catch {
            throw CredentialRequestError.unusable(
                "The deferred credential request could not be encrypted: \(error.localizedDescription)"
            )
        }
        guard let request = HTTPCall.jwtPost(
            url: endpoint, body: encrypted, attestation: attestation
        ) else {
            throw CredentialRequestError.unusable(
                "The deferred credential request could not be built for \(endpoint)"
            )
        }
        return request
    }

    /// Section 9.3's `interval`, when the issuer named one.
    private func pendingInterval(from data: Data) -> Double? {
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        guard let value = json?["interval"] as? Double, value > 0 else { return nil }
        return value
    }

    private static let useDPoPNonce = "use_dpop_nonce"
    private static let issuancePending = "issuance_pending"
}
