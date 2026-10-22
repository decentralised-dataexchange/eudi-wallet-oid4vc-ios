//
//  PresentationBuilder.swift
//  eudiWalletOidcIos
//

import Foundation

/// Turns the credentials the user selected into the elements of a `vp_token`.
///
/// Credentials are presented in the order given. Under DCQL each credential becomes one
/// presentation. Under a presentation definition the draft shapes apply: SD-JWTs stay one each,
/// every mdoc goes into one DeviceResponse and every W3C VC into one presentation, each placed
/// where the first of its kind was.
public struct PresentationBuilder {

    public init() {}

    /// - Throws: `PresentationError` when a proof cannot be made.
    public func build(_ selected: [SelectedCredential], inputs: PresentationInputs) async throws -> [Presentation] {
        guard !selected.isEmpty else { return [] }
        let withFormat = selected.map { ($0, Self.format(of: $0.credential)) }
        let draft = inputs.request.dcqlQuery == nil
        var transcript: SessionTranscript?
        func sessionTranscript() async -> SessionTranscript {
            if let transcript { return transcript }
            var thumbprint = inputs.encryptionKeyThumbprint
            if thumbprint == nil { thumbprint = await Self.encryptionKeyThumbprint(inputs.request) }
            let made = SessionTranscript.forRequest(inputs.request, encryptionKeyThumbprint: thumbprint)
            transcript = made
            return made
        }
        let mdoc = MdocVpTokenBuilder()
        var out: [Presentation] = []
        var w3cDone = false
        var mdocDone = false
        for (credential, format) in withFormat {
            switch format {
            case .sdJwt:
                out.append(try SdJwtVpTokenBuilder().present(credential, inputs))
            case .mdoc where draft:
                guard !mdocDone else { continue }
                mdocDone = true
                let all = withFormat.filter { $0.1 == .mdoc }.map { $0.0 }
                let transcript = await sessionTranscript()
                out.append(try mdoc.presentAll(all, inputs, transcript))
            case .mdoc:
                let transcript = await sessionTranscript()
                out.append(try mdoc.present(credential, inputs, transcript))
            case .w3cVp where draft:
                guard !w3cDone else { continue }
                w3cDone = true
                let all = withFormat.filter { $0.1 == .w3cVp }.map { $0.0 }
                out.append(try JwtVpTokenBuilder().aggregate(all, inputs))
            case .w3cVp:
                out.append(try JwtVpTokenBuilder().present(credential, inputs))
            case nil:
                throw PresentationError.unsupportedFormat(credential.entryId)
            }
        }
        return out
    }

    /// mdoc when there is no `.`, SD-JWT when there is a `~` or a `vct`, W3C VC for any other JWT.
    static func format(of credential: String) -> PresentationFormat? {
        guard !credential.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        if !credential.contains(".") { return .mdoc }
        if credential.contains("~") { return .sdJwt }
        let parts = credential.split(separator: ".")
        guard parts.count > 1, let payload = String(parts[1]).decodeBase64(),
              let claims = UIApplicationUtils.shared.convertStringToDictionary(text: payload) else { return nil }
        return claims["vct"] != nil ? .sdJwt : .w3cVp
    }

    /// The credential's own key, or the holder's when it has none.
    static func key(for selected: SelectedCredential, _ inputs: PresentationInputs) -> SecureKeyProtocol? {
        if let keyId = selected.keyId, !keyId.isEmpty { return SecureEnclaveHandler.presentationKey(keyId) }
        return inputs.holderKey
    }

    /// The RFC 7638 thumbprint of the verifier's encryption key from the request's client metadata,
    /// for the mdoc session transcript; nil when there is none.
    public static func encryptionKeyThumbprint(_ request: PresentationRequest) async -> [UInt8]? {
        guard let jwk = await VerifierJwk().deriveVerifiersJWKFromClientMetadata(presentationRequest: request) else { return nil }
        return computeJwkThumbprintBytes(jwk: jwk)
    }
}
