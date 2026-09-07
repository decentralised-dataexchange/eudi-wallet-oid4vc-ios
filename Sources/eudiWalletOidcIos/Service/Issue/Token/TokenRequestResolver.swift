//
//  TokenRequestResolver.swift
//

import Foundation

/// Exchanges a code for an access token: build the body once, send it, read the answer.
///
/// No transport registry here, unlike the authorization request -- the *offer* decides the grant,
/// so there is nothing to select at runtime.
///
/// Mirrors `TokenRequestResolver` in the Android SDK.
struct TokenRequestResolver {

    let policy: TokenRequestPolicy

    init(policy: TokenRequestPolicy = .standard) {
        self.policy = policy
    }

    func resolve(
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation? = nil,
        grant: TokenGrant,
        authorizationDetails: String? = nil,
        dpopNonce: String? = nil,
        urlSession: URLSession = URLSession(configuration: .default)
    ) async -> TokenResponse {
        guard let tokenEndpoint = session.authConfig?.tokenEndpoint, !tokenEndpoint.isEmpty else {
            return failure("This issuer's authorization server declared no token endpoint")
        }

        // Section 6.1: a Transaction Code is required by the *offer*, not by whether the caller has
        // one. Failing here saves a round trip and says something the user can act on.
        if case let .preAuthorized(_, txCode) = grant,
           session.requiresTransactionCode,
           txCode?.isEmpty != false {
            return failure("This offer requires a transaction code")
        }

        // TS3: the DPoP key must be the one the attestation names in `cnf`. A mismatch is rejected
        // as invalid_client_attestation with nothing in the response to say why.
        if attestation?.dpopKeyMatchesAttestation == false {
            debugPrint("the DPoP key is not the one the wallet attestation names in cnf")
        }

        let parameters = TokenRequestParameters.build(
            session: session,
            wallet: wallet,
            attestation: attestation,
            grant: grant,
            authorizationDetails: authorizationDetails,
            policy: policy
        )

        do {
            return try await send(
                tokenEndpoint: tokenEndpoint,
                parameters: parameters,
                attestation: attestation,
                dpopNonce: dpopNonce,
                allowRetry: true,
                urlSession: urlSession
            )
        } catch let error as TokenRequestError {
            return TokenResponse(error: error.asEUDIError)
        } catch {
            return failure(error.localizedDescription)
        }
    }

    private func send(
        tokenEndpoint: String,
        parameters: TokenRequestParameters,
        attestation: WalletAttestation?,
        dpopNonce: String?,
        allowRetry: Bool,
        urlSession: URLSession
    ) async throws -> TokenResponse {
        guard var request = HTTPCall.formPost(
            url: tokenEndpoint,
            parameters: parameters.asDictionary(),
            attestation: attestation
        ) else {
            throw TokenRequestError.unusable("This issuer's token endpoint is not a usable URL")
        }

        let dpop = attestation?.dpopProof(for: tokenEndpoint, nonce: dpopNonce)
        if let dpop { request.setValue(dpop, forHTTPHeaderField: "DPoP") }

        let result = try await HTTPCall.send(
            request,
            tag: "token-request",
            session: urlSession,
            onTransportFailure: tokenTransportFailure
        )

        // RFC 9449 section 8.2: a nonce may also arrive on a success, rotating the one in use.
        let issuedNonce = result.header("DPoP-Nonce")

        if result.isSuccessful {
            var model = (try? JSONDecoder().decode(TokenResponse.self, from: result.data))
                ?? TokenResponse()
            model.lpid = result.header("legal-pid-attestation")
            model.lpidPop = result.header("legal-pid-attestation-pop")
            model.dpopKey = attestation?.dpopKey
            model.dpopNonce = issuedNonce ?? dpopNonce
            return model
        }

        let error = ErrorHandler.processError(
            data: result.data,
            contentType: result.contentType,
            httpStatus: result.status
        )

        // RFC 9449 section 8: `400` + `use_dpop_nonce` + a `DPoP-Nonce` header. Exactly once.
        let demandsNonce = result.status == 400
            && error?.errorCode == "use_dpop_nonce"
            && issuedNonce?.isEmpty == false
        if demandsNonce, allowRetry, policy.retryOnDPoPNonce, attestation?.hasDPoPKey == true {
            debugPrint("token endpoint asked for a DPoP nonce; retrying once")
            return try await send(
                tokenEndpoint: tokenEndpoint,
                parameters: parameters,
                attestation: attestation,
                dpopNonce: issuedNonce,
                allowRetry: false,
                urlSession: urlSession
            )
        }

        var model = TokenResponse(error: error ?? EUDIError(
            message: "The token request was refused (HTTP \(result.status))",
            httpStatus: result.status
        ))
        model.dpopNonce = issuedNonce
        return model
    }

    private func failure(_ reason: String) -> TokenResponse {
        TokenResponse(error: EUDIError(message: reason))
    }
}

/// Why a token request could not be completed. Internal: the resolver converts it into a reason.
enum TokenRequestError: Error {
    case requestFailed(String?)
    case unusable(String)

    var asEUDIError: EUDIError {
        switch self {
        case let .requestFailed(detail):
            return EUDIError(message: detail?.isEmpty == false ? detail : "The token request failed")
        case let .unusable(detail):
            return EUDIError(message: detail)
        }
    }
}

/// @see ``HTTPCall``
func tokenTransportFailure(_ detail: String?, _ failingURL: String?) -> Error {
    TokenRequestError.requestFailed(detail)
}
