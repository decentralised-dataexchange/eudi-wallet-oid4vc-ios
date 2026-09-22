//
//  CredentialRequestResolver.swift
//

import Foundation

/// Asks the issuer for a credential: obtain a nonce, sign a proof, send, read the answer.
///
/// A pipeline rather than a registry -- the token response decides the request's shape, so there is
/// nothing to select at runtime.
///
/// Three things this can do that the previous implementation could not, all downstream of
/// ``HTTPCall`` replacing the bare `NetworkLogger.send`, which left the status and headers to be
/// re-read by hand at each branch and dropped on most of them:
///
///  - a rejection carries the issuer's own `error` code **and** the HTTP status;
///  - section 8.3.1's stale-nonce retry, since the fresh `c_nonce` arrives in the error body;
///  - RFC 9449's DPoP nonce retry, since that one arrives in a header.
///
/// Mirrors `CredentialRequestResolver` in the Android SDK.
struct CredentialRequestResolver {

    let policy: CredentialRequestPolicy
    let keyHandler: SecureKeyProtocol

    init(policy: CredentialRequestPolicy = .standard, keyHandler: SecureKeyProtocol) {
        self.policy = policy
        self.keyHandler = keyHandler
    }

    /// - Parameter nonce: overrides the `c_nonce`. Left nil the resolver obtains one itself, from
    ///   the Nonce Endpoint when the issuer publishes one (section 7 -- it is unauthenticated) and
    ///   otherwise from the token response. Callers used to do this, which is why a single nonce
    ///   was reused for every credential in a multi-credential offer.
    func resolve(
        session: IssuanceSession,
        wallet: WalletIdentity,
        token: TokenResponse,
        subject: CredentialSubject,
        issuer: String?,
        attestation: WalletAttestation? = nil,
        keyAttestation: String? = nil,
        encryption: CredentialEncryption? = nil,
        nonce: String? = nil,
        dpopNonce: String? = nil,
        urlSession: URLSession = URLSession(configuration: .default)
    ) async -> CredentialOutcome {

        guard let endpoint = session.issuerConfig?.credentialEndpoint, !endpoint.isEmpty else {
            return .failed(error: CredentialRequestError.noCredentialEndpoint.asEUDIError)
        }

        let resolvedEncryption = (encryption ?? CredentialEncryption()).resolved(against: session)

        // `??` takes an autoclosure, which cannot carry an await -- so the fetch happens first.
        let resolvedNonce: String?
        if let nonce, !nonce.isEmpty {
            resolvedNonce = nonce
        } else {
            resolvedNonce = await obtainNonce(session: session, token: token, urlSession: urlSession)
        }

        do {
            return try await send(
                endpoint: endpoint,
                session: session,
                wallet: wallet,
                token: token,
                subject: subject,
                issuer: issuer,
                attestation: attestation,
                keyAttestation: keyAttestation,
                encryption: resolvedEncryption,
                nonce: resolvedNonce,
                dpopNonce: dpopNonce ?? token.dpopNonce,
                allowRetry: true,
                urlSession: urlSession
            )
        } catch let error as CredentialRequestError {
            debugPrint("credential request failed: \(error.asEUDIError.message ?? "")")
            return .failed(error: error.asEUDIError)
        } catch {
            return .failed(error: EUDIError(message: error.localizedDescription))
        }
    }

    /// Section 7: a Credential Issuer that requires `c_nonce` values "MUST offer a Nonce Endpoint",
    /// and that endpoint "is not a protected resource". Draft issuers instead return `c_nonce` with
    /// the token, so that is the fallback.
    private func obtainNonce(
        session: IssuanceSession,
        token: TokenResponse,
        urlSession: URLSession
    ) async -> String? {
        if let nonceEndpoint = session.issuerConfig?.nonceEndPoint, !nonceEndpoint.isEmpty {
            let fetched = await NonceService().fetchNonceEndpoint(
                accessToken: token.accessToken,
                nonceEndPoint: nonceEndpoint,
                urlSession: urlSession
            )
            if let fetched, !fetched.isEmpty { return fetched }
            debugPrint("the nonce endpoint returned nothing; falling back to the token's c_nonce")
        }
        return token.cNonce
    }

    private func send(
        endpoint: String,
        session: IssuanceSession,
        wallet: WalletIdentity,
        token: TokenResponse,
        subject: CredentialSubject,
        issuer: String?,
        attestation: WalletAttestation?,
        keyAttestation: String?,
        encryption: CredentialEncryption,
        nonce: String?,
        dpopNonce: String?,
        allowRetry: Bool,
        urlSession: URLSession
    ) async throws -> CredentialOutcome {

        let proof = try await CredentialProofFactory.create(
            session: session,
            wallet: wallet,
            keyHandler: keyHandler,
            issuer: issuer,
            nonce: nonce,
            subject: subject,
            keyAttestation: keyAttestation
        )

        let params = try CredentialRequestParameters.build(
            subject: subject,
            proof: proof,
            session: session,
            encryption: encryption,
            policy: policy
        )

        debugPrint("""
            credential request: endpoint=\(endpoint) subject=\(subject.describedForLog) \
            proofs=\(params["proofs"] != nil) nonce=\(nonce?.isEmpty == false ? "present" : "none") \
            keyAttestation=\(keyAttestation != nil) \
            encryptedRequest=\(encryption.requestEncryptionRequired)
            """)

        var request = try await buildRequest(
            endpoint: endpoint,
            params: params,
            encryption: encryption,
            attestation: attestation
        )

        // Section 8.2 does not say which scheme to use; RFC 9449 does -- the token's own
        // `token_type` is what says whether the access token is sender-constrained. The previous
        // implementation branched on a caller-supplied `isDpopSUpported` flag instead, so a
        // caller could send `Authorization: DPoP ...` with no proof attached.
        let accessToken = token.accessToken ?? ""
        let wantsDPoP = token.tokenType?.caseInsensitiveCompare("DPoP") == .orderedSame
            || attestation?.hasDPoPKey == true
        var dpop: String?
        if wantsDPoP {
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
            tag: "credential-request",
            session: urlSession,
            onTransportFailure: credentialTransportFailure
        )

        let issuedDPoPNonce = result.header("DPoP-Nonce")

        if result.isSuccessful {
            return try CredentialResponseReader.read(result, encryption: encryption)
        }

        let error = ErrorHandler.processError(
            data: result.data,
            contentType: result.contentType,
            httpStatus: result.status
        )

        // RFC 9449 section 8, the same challenge the token endpoint answers -- the credential
        // endpoint has never handled it.
        if allowRetry, policy.retryOnDPoPNonce, attestation?.hasDPoPKey == true,
           result.status == 400, error?.errorCode == Self.useDPoPNonce,
           let issuedDPoPNonce, !issuedDPoPNonce.isEmpty {
            debugPrint("credential endpoint asked for a DPoP nonce; retrying once")
            return try await send(
                endpoint: endpoint, session: session, wallet: wallet, token: token,
                subject: subject, issuer: issuer, attestation: attestation, keyAttestation: keyAttestation,
                encryption: encryption, nonce: nonce, dpopNonce: issuedDPoPNonce,
                allowRetry: false, urlSession: urlSession
            )
        }

        // Section 8.3.1: "The Credential Issuer MAY return a new `c_nonce` value in an error
        // response" -- so a rejected proof is often recoverable by signing again with it.
        if allowRetry, policy.retryOnStaleNonce,
           error?.errorCode == Self.invalidProof || error?.errorCode == Self.invalidNonce,
           let fresh = freshNonce(from: result.data), !fresh.isEmpty {
            debugPrint("issuer rejected the proof and supplied a fresh nonce; retrying once")
            return try await send(
                endpoint: endpoint, session: session, wallet: wallet, token: token,
                subject: subject, issuer: issuer, attestation: attestation, keyAttestation: keyAttestation,
                encryption: encryption, nonce: fresh, dpopNonce: dpopNonce,
                allowRetry: false, urlSession: urlSession
            )
        }

        // A 500 rarely carries a usable body, so the request that produced it is the evidence.
        // The proof and any key attestation are sent to this issuer anyway; neither is a secret
        // from it.
        debugPrint("credential endpoint \(result.status) error=\(error?.errorCode ?? error?.message ?? "-")")
        debugPrint("credential endpoint \(result.status) body=\(String(data: result.data, encoding: .utf8) ?? "<empty>")")
        debugPrint("the request it refused: \(params)")

        return .failed(error: error ?? CredentialRequestError.rejected(
            status: result.status, body: result.data, contentType: result.contentType
        ).asEUDIError)
    }

    private func buildRequest(
        endpoint: String,
        params: [String: Any],
        encryption: CredentialEncryption,
        attestation: WalletAttestation?
    ) async throws -> URLRequest {
        // Section 10: the client "MUST" encrypt when the issuer sets `encryption_required`.
        guard encryption.requestEncryptionRequired else {
            guard let request = HTTPCall.jsonPost(
                url: endpoint, body: params, attestation: attestation
            ) else {
                throw CredentialRequestError.unusable(
                    "The credential request could not be built for \(endpoint)"
                )
            }
            return request
        }

        guard let jwk = encryption.request?.jwks?.first?.dictionary else {
            throw CredentialRequestError.unusable(
                "This issuer requires an encrypted credential request but published no key"
            )
        }

        let encrypted: String
        do {
            encrypted = try await JWEEncryptor().encrypt(
                payload: params,
                jwks: jwk,
                // The one suite this SDK implements. This used to pass the **response**
                // metadata's `enc_values_supported` while encrypting the *request* -- reading one
                // direction's list to pick the other's cipher. `credential_request_encryption`
                // carries no `enc_values_supported` of its own in the model, and `JWEDecryptor`
                // hardcodes A128CBC-HS256 regardless, so naming it here is the honest form of what
                // was already happening.
                supportedEncryptions: [CredentialRequestParameters.contentEncryption]
            )
        } catch {
            // Failing here used to assign `encryptRequest = ""` and send an empty body, which the
            // issuer answers with a generic error that says nothing about encryption.
            throw CredentialRequestError.unusable(
                "The credential request could not be encrypted: \(error.localizedDescription)"
            )
        }

        guard let request = HTTPCall.jwtPost(
            url: endpoint, body: encrypted, attestation: attestation
        ) else {
            throw CredentialRequestError.unusable(
                "The credential request could not be built for \(endpoint)"
            )
        }
        return request
    }

    /// The `c_nonce` an issuer may put in an error response, section 8.3.1.
    private func freshNonce(from data: Data) -> String? {
        ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["c_nonce"] as? String
    }

    private static let useDPoPNonce = "use_dpop_nonce"
    private static let invalidProof = "invalid_proof"
    private static let invalidNonce = "invalid_nonce"
}
