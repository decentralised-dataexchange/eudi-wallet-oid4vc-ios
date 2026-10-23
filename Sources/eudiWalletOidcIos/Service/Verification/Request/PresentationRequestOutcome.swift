//
//  PresentationRequestOutcome.swift
//  eudiWalletOidcIos
//

import Foundation

/// What resolving scanned data into a presentation request produced.
///
/// Replaces a tuple of two optionals that left callers to work out which of "nothing scanned",
/// "request refused" and "request ready" they were looking at.
public enum PresentationRequestOutcome {

    /// The request is ready for credential matching.
    case resolved(ResolvedPresentationRequest)

    /// The data was not a presentation request, or was one the policy or the spec refuses.
    case failed(EUDIError)
}

/// A presentation request ready for credential matching.
public struct ResolvedPresentationRequest {

    /// The parsed request, with any `presentation_definition_uri` and `client_metadata_uri`
    /// already dereferenced.
    public let request: PresentationRequest

    /// Which revision of OpenID4VP the request follows.
    public let specVersion: PresentationRequestSpecVersion

    /// The registry name of the transfer mechanism that carried it, for logs.
    public let source: String

    /// What the client identifier check established about the verifier: which prefix, whether
    /// the request is authenticated, whether the key is anchored.
    public let verifier: VerifierIdentity

    /// The request's `transaction_data`, decoded and checked against the query.
    public let transactionData: [TransactionDataEntry]
}
