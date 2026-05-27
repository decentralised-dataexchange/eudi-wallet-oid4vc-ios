import Foundation
import CryptoKit
import SwiftCBOR

/// Builds the SessionTranscript for ISO 18013-7 Annex C (non-OpenID DC API).
///
/// SessionTranscript = [null, null, ["dcapi", SHA-256(CBOR([encryptionInfoBase64, origin]))]]
///
/// The dcapiInfo is a CBOR array of two text strings:
///   [encryptionInfoBase64: tstr, origin: tstr]
/// where encryptionInfoBase64 is the original base64url string from the request.
func buildSessionTranscriptForDCAPI(
    encryptionInfoBase64: String,
    origin: String
) -> (cbor: CBOR, bytes: [UInt8]) {

    // Step 1: dcapiInfo = CBOR([encryptionInfoBase64, origin])
    let dcapiInfo: CBOR = .array([
        .utf8String(encryptionInfoBase64),
        .utf8String(origin)
    ])
    let dcapiInfoBytes = encodeCBOR(dcapiInfo)

    // Step 2: SHA-256 hash
    let dcapiInfoHash = Array(SHA256.hash(data: Data(dcapiInfoBytes)))

    // Step 3: handover = ["dcapi", dcapiInfoHash]
    let handover: CBOR = .array([
        .utf8String("dcapi"),
        .byteString(dcapiInfoHash)
    ])

    // Step 4: SessionTranscript = [null, null, handover]
    let sessionTranscript: CBOR = .array([
        .null,
        .null,
        handover
    ])

    let sessionTranscriptBytes = encodeCBOR(sessionTranscript)
    return (cbor: sessionTranscript, bytes: sessionTranscriptBytes)
}
