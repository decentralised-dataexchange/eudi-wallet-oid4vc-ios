//
//  PresentationSubmitter.swift
//  eudiWalletOidcIos
//

import Foundation

/// The response pipeline: response mode, response URI, the presentations, the submission, the id
/// token, the encoding, and then the POST or the hand-over to the host.
///
/// A proof that cannot be made refuses the whole response and sends nothing: a verifier is never
/// shown an unsigned credential in place of a presentation.
struct PresentationSubmitter {

    var builder = PresentationBuilder()
    var encoder = AuthorizationResponseEncoder()
    var client = DirectPostClient()

    /// - Parameter holderKey: the wallet's DID key, which signs W3C presentations and the id token,
    ///   and any credential selected without a key id.
    func submit(_ request: PresentationRequest, selected: [SelectedCredential], identity: WalletIdentity,
                holderKey: SecureKeyProtocol, attestation: WalletAttestation?,
                authentication: AuthenticationMethods?) async -> PresentationOutcome {
        do {
            let mode = ResponseMode.of(request)
            if case .unsupported(let raw) = mode { throw SubmissionError.unsupportedResponseMode(raw) }
            let effective = Self.effective(request, mode)
            let responseUri = [effective.responseUri, effective.redirectUri]
                .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }.first { !$0.isEmpty }
            if !mode.deliveredByHost && responseUri == nil { throw SubmissionError.noResponseUri }

            let fields = try await prepare(effective, mode: mode, selected: selected, did: identity.did, holderKey: holderKey,
                                           authentication: authentication)
            if mode.deliveredByHost { return .delivered(parameters: fields) }
            return await client.post(responseUri ?? "", fields: fields, headers: Self.headers(attestation))
        } catch let error as PresentationError {
            return refused(error.localizedDescription, "invalid_request")
        } catch let error as SubmissionError {
            return refused(error.errorDescription, error.oauthError)
        } catch {
            return refused(error.localizedDescription, "invalid_request")
        }
    }

    /// The encoded response parameters for `mode`, without sending them.
    ///
    /// - Throws: `PresentationError` when a proof cannot be made, `SubmissionError` when the
    ///   response cannot be encoded for the mode.
    func prepare(_ request: PresentationRequest, mode: ResponseMode, selected: [SelectedCredential], did: String,
                 holderKey: SecureKeyProtocol, authentication: AuthenticationMethods?) async throws -> [String: String] {
        let wantsVpToken = request.dcqlQuery != nil || (request.responseType ?? "").contains("vp_token")
        var presentations: [Presentation] = []
        if wantsVpToken {
            let inputs = PresentationInputs(
                request: request,
                holderDid: did,
                holderKey: holderKey,
                transactionDataHashes: LegacyTransactionData.hashes(request, entryIds: Self.entryIds(request, selected)),
                strongCustomerAuthentication: LegacyTransactionData.isStrongCustomerAuthentication(request, flag: authentication != nil),
                authentication: authentication)
            presentations = try await builder.build(selected, inputs: inputs)
        }
        var submission: PresentationSubmissionModel?
        if request.dcqlQuery == nil, wantsVpToken {
            let definition = try? VerificationService.processPresentationDefinition(request.presentationDefinition)
            submission = PresentationSubmissionBuilder().build(presentations, definition: definition)
        }
        var idToken: String?
        if request.dcqlQuery == nil, (request.responseType ?? "").contains("id_token") {
            idToken = await IdTokenGenerator().generate(request, did: did, keyHandler: holderKey)
        }
        let response = AuthorizationResponseParameters.build(request, presentations: presentations, submission: submission, idToken: idToken)
        if response.isEmpty { throw SubmissionError.nothingToSend }
        return try await encoder.encode(mode, response, request)
    }

    /// Appendix A.4: over the DC API the audience is the origin, prefixed. Applied on a copy so the
    /// caller's request is not changed under it.
    static func effective(_ request: PresentationRequest, _ mode: ResponseMode) -> PresentationRequest {
        var effective = request
        if mode.deliveredByHost, let clientId = request.clientId, !clientId.hasPrefix("origin:") {
            effective.clientId = "origin:\(clientId)"
        }
        return effective
    }

    /// The entry ids the transaction data may name: every DCQL credential query, or the selection.
    private static func entryIds(_ request: PresentationRequest, _ selected: [SelectedCredential]) -> [String] {
        request.dcqlQuery?.credentials.map { $0.id } ?? selected.map { $0.entryId }
    }

    /// The wallet unit attestation headers, only when there is an attestation. A trailing `~` is
    /// dropped, as the attestation is sometimes stored in SD-JWT form.
    static func headers(_ attestation: WalletAttestation?) -> [String: String] {
        guard let jwt = attestation?.attestationJwt?.trimmingCharacters(in: .whitespacesAndNewlines), !jwt.isEmpty else { return [:] }
        var headers = ["OAuth-Client-Attestation": jwt.hasSuffix("~") ? String(jwt.dropLast()) : jwt]
        if let pop = attestation?.proofOfPossession, !pop.isEmpty { headers["OAuth-Client-Attestation-PoP"] = pop }
        return headers
    }

    private func refused(_ message: String?, _ code: String) -> PresentationOutcome {
        .refused(EUDIError(message: message, errorCode: code))
    }
}
