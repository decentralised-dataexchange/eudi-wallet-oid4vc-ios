//
//  SessionTranscript.swift
//  eudiWalletOidcIos
//

import Foundation
import CryptoKit
import SwiftCBOR

/// The ISO 18013-5 SessionTranscript an mdoc device signature is bound to, in the shapes
/// OpenID4VP 1.0 Appendix B.2.6 defines and the one ISO/IEC TS 18013-7 Annex B defines.
///
/// All three are `[null, null, Handover]`: "DeviceEngagementBytes MUST be null. EReaderKeyBytes
/// MUST be null." They differ in the handover.
struct SessionTranscript {
    let array: CBOR
    var bytes: [UInt8] { encodeCBOR(array) }

    /// B.2.6.1, redirect flows: `Handover = ["OpenID4VPHandover", sha256(OpenID4VPHandoverInfo)]`
    /// with `OpenID4VPHandoverInfo = [client_id, nonce, jwk_thumbprint or null, response_uri]`.
    /// The response URI is left out when the request has none, as the previous code did.
    static func openId4Vp(clientId: String, nonce: String, responseUri: String?,
                          encryptionKeyThumbprint: [UInt8]?) -> SessionTranscript {
        var info: [CBOR] = [.utf8String(clientId), .utf8String(nonce), thumbprint(encryptionKeyThumbprint)]
        responseUri.map { info.append(.utf8String($0)) }
        return withHandover("OpenID4VPHandover", info)
    }

    /// B.2.6.2, Digital Credentials API: `Handover = ["OpenID4VPDCAPIHandover", sha256(info)]` with
    /// `info = [origin, nonce, jwk_thumbprint or null]`. "It MUST NOT be prefixed with origin:."
    static func dcApi(origin: String, nonce: String, encryptionKeyThumbprint: [UInt8]?) -> SessionTranscript {
        withHandover("OpenID4VPDCAPIHandover", [.utf8String(origin), .utf8String(nonce), thumbprint(encryptionKeyThumbprint)])
    }

    /// ISO/IEC TS 18013-7 section B.4.4, the draft profile used with a presentation definition:
    /// `Handover = [clientIdHash, responseUriHash, nonce]` where
    /// `clientIdHash = sha256(cbor([client_id, mdocGeneratedNonce]))` and
    /// `responseUriHash = sha256(cbor([response_uri, mdocGeneratedNonce]))`.
    ///
    /// The profile wants a random `mdocGeneratedNonce` echoed to the verifier as the JWE `apu`
    /// header. The response encryption sets `apu` to the client id, so the default here keeps both
    /// ends consistent; a random nonce needs both places changed together.
    static func annexB(clientId: String, nonce: String, responseUri: String,
                       mdocGeneratedNonce: String? = nil) -> SessionTranscript {
        let generated = mdocGeneratedNonce ?? clientId
        let handover: CBOR = .array([.byteString(sha256(.array([.utf8String(clientId), .utf8String(generated)]))),
                                     .byteString(sha256(.array([.utf8String(responseUri), .utf8String(generated)]))),
                                     .utf8String(nonce)])
        return SessionTranscript(array: .array([.null, .null, handover]))
    }

    /// The transcript the request calls for: Annex B when it carries a presentation definition,
    /// the DC API handover for the `dc_api` response modes, the OpenID4VP handover otherwise.
    static func forRequest(_ request: PresentationRequest, encryptionKeyThumbprint: [UInt8]?) -> SessionTranscript {
        let nonce = request.nonce ?? ""
        let isDcApi = ResponseMode.of(request).deliveredByHost
        let rawClientId = request.clientId ?? ""
        let clientId = isDcApi && rawClientId.hasPrefix("origin:") ? String(rawClientId.dropFirst("origin:".count)) : rawClientId
        let responseUri = request.responseUri ?? request.redirectUri
        let usesPresentationDefinition = request.presentationDefinition?.isEmpty == false
            || request.presentationDefinitionUri?.isEmpty == false
        if usesPresentationDefinition {
            return annexB(clientId: clientId, nonce: nonce, responseUri: responseUri ?? "")
        }
        if isDcApi {
            return dcApi(origin: clientId, nonce: nonce, encryptionKeyThumbprint: encryptionKeyThumbprint)
        }
        return openId4Vp(clientId: clientId, nonce: nonce, responseUri: responseUri, encryptionKeyThumbprint: encryptionKeyThumbprint)
    }

    static func withHandover(_ label: String, _ info: [CBOR]) -> SessionTranscript {
        let handover: CBOR = .array([.utf8String(label), .byteString(sha256(.array(info)))])
        return SessionTranscript(array: .array([.null, .null, handover]))
    }

    private static func thumbprint(_ bytes: [UInt8]?) -> CBOR {
        bytes.map { .byteString($0) } ?? .null
    }

    private static func sha256(_ item: CBOR) -> [UInt8] {
        Array(SHA256.hash(data: Data(encodeCBOR(item))))
    }
}
