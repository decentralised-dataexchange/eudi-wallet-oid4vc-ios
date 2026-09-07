//
//  CredentialRequestError.swift
//

import Foundation

/// Why a credential request could not be completed.
///
/// Internal: the resolver turns each of these into ``CredentialOutcome/failed(error:)``, so a
/// caller never catches one. It exists so the resolver's own failure paths carry a reason -- the
/// previous implementation had a dozen `return nil` sites and no way to tell them apart.
///
/// Mirrors `CredentialRequestException` in the Android SDK.
enum CredentialRequestError: Error {

    /// The issuer metadata named no credential endpoint.
    case noCredentialEndpoint

    /// The proof could not be built or signed.
    case proofFailed(String)

    /// Section 8.2 makes `nonce` REQUIRED in the proof when the issuer publishes a Nonce Endpoint.
    /// Sending one without it produces `invalid_proof` a round trip later, with nothing saying why.
    case noNonce

    /// The request reached the issuer and was refused.
    case rejected(status: Int, body: Data?, contentType: String?)

    /// The request never completed -- network, DNS, timeout.
    case requestFailed(String?)

    /// The issuer answered with something this wallet cannot read, or the request could not be
    /// assembled at all.
    case unusable(String, status: Int? = nil)

    var asEUDIError: EUDIError {
        switch self {
        case .noCredentialEndpoint:
            return EUDIError(message: "This issuer published no credential endpoint")

        case let .proofFailed(detail):
            return EUDIError(message: detail)

        case .noNonce:
            return EUDIError(
                message: "This issuer requires a c_nonce in the proof and none could be obtained"
            )

        case let .rejected(status, body, contentType):
            // Read through ErrorHandler so the issuer's own `error` code survives alongside the
            // sentence. The previous implementation called it without `httpStatus`, dropping the
            // status on every credential failure.
            if let parsed = ErrorHandler.processError(
                data: body, contentType: contentType, httpStatus: status
            ), parsed.message?.isEmpty == false {
                return parsed
            }
            return EUDIError(
                message: "The credential request was refused (HTTP \(status))",
                httpStatus: status,
                raw: body.flatMap { String(data: $0, encoding: .utf8) }
            )

        case let .requestFailed(detail):
            return EUDIError(
                message: detail?.isEmpty == false ? detail : "The credential request failed"
            )

        case let .unusable(detail, status):
            return EUDIError(message: detail, httpStatus: status)
        }
    }
}

/// @see ``HTTPCall``
func credentialTransportFailure(_ detail: String?, _ failingURL: String?) -> Error {
    CredentialRequestError.requestFailed(detail)
}
