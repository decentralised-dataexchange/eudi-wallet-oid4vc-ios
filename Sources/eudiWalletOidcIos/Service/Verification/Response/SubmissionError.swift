//
//  SubmissionError.swift
//  eudiWalletOidcIos
//

import Foundation

/// Why a response could not be prepared or sent. The description is meant for a user.
public enum SubmissionError: LocalizedError, Equatable {

    /// Section 8.2: `response_uri` is REQUIRED with direct_post; the draft `redirect_uri` is
    /// accepted in its place.
    case noResponseUri
    case unsupportedResponseMode(String)
    /// Section 8.3: no key in the client metadata the response could be encrypted to.
    case noEncryptionKey
    /// Section 8.3: the verifier's key algorithm or content encryption is one this SDK does not support.
    case encryptionUnsupported(String)
    case encryptionFailed
    /// The response would carry neither a `vp_token` nor an `id_token`, as with a response type
    /// this SDK does not know.
    case nothingToSend

    public var errorDescription: String? {
        switch self {
        case .noResponseUri: return "The request names no response_uri to send the presentation to"
        case .unsupportedResponseMode(let raw): return "The response mode '\(raw)' is not supported"
        case .noEncryptionKey: return "The verifier asked for an encrypted response but published no encryption key"
        case .encryptionUnsupported(let detail): return "The response cannot be encrypted: \(detail)"
        case .encryptionFailed: return "The response could not be encrypted"
        case .nothingToSend: return "The request asks for nothing this wallet can send"
        }
    }

    /// The OAuth error code a refusal carries.
    var oauthError: String {
        switch self {
        case .nothingToSend: return "unsupported_response_type"
        default: return "invalid_request"
        }
    }
}
