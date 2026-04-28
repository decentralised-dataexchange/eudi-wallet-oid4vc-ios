//
//  DeviceAuth.swift
//  eudiWalletOidcIos

import Foundation
import CryptoKit
import SwiftCBOR
import OrderedCollections
import Security

// MARK: - SessionTranscript (OID4VP Appendix B.2.6.1)

/// Builds the full SessionTranscript for the OpenID4VP redirect flow.
///
/// Per ISO 18013-5 §9.1.5.1 + OID4VP Appendix B.2.6.1:
///   SessionTranscript = [null, null, OpenID4VPHandover]
///   OpenID4VPHandover  = ["OpenID4VPHandover", SHA-256(HandoverInfoBytes)]
///   HandoverInfo       = [clientId, nonce, jwkThumbprint, responseUri]

func buildSessionTranscriptForOpenID4VP(
    clientId: String,
    nonce: String,
    responseUri: String? = nil,
    jwkThumbprint: [UInt8]? = nil,
    responseMode: String? = nil
) -> (cbor: CBOR, bytes: [UInt8]) {

    let isDcApi = responseMode == ResponseMode.dcApi.rawValue
        || responseMode == ResponseMode.dcApiJWT.rawValue

    // Step 1: HandoverInfo = [clientId, nonce, jwkThumbprint?, responseUri?]
    var handoverInfoItems: [CBOR] = [
        .utf8String(clientId),
        .utf8String(nonce),
        jwkThumbprint != nil ? .byteString(jwkThumbprint!) : .null
    ]
    if let uri = responseUri {
        handoverInfoItems.append(.utf8String(uri))
    }
    let handoverInfo: CBOR = .array(handoverInfoItems)
    let handoverInfoBytes = encodeCBOR(handoverInfo)

    // Step 2: SHA-256 hash of HandoverInfo bytes
    let handoverInfoHash = Array(SHA256.hash(data: Data(handoverInfoBytes)))

    // Step 3: OpenID4VPHandover / OpenID4VPDCAPIHandover = [<label>, hash]
    let handoverLabel = isDcApi ? "OpenID4VPDCAPIHandover" : "OpenID4VPHandover"
    let handoverArray: CBOR = .array([
        .utf8String(handoverLabel),
        .byteString(handoverInfoHash)
    ])

    // Step 4: SessionTranscript = [null, null, OpenID4VPHandover]
    let sessionTranscript: CBOR = .array([
        .null,           // DeviceEngagement (not used in OID4VP)
        .null,           // EReaderKey (not used in OID4VP)
        handoverArray
    ])

    let sessionTranscriptBytes = encodeCBOR(sessionTranscript)
    return (cbor: sessionTranscript, bytes: sessionTranscriptBytes)
}

// MARK: - DeviceNameSpaces (ISO 18013-5 §8.3.2.1.2.2)

/// Encodes DeviceNameSpaces as an empty map wrapped in CBOR tag 24.
///
///   DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)
///   DeviceNameSpaces = {} (empty when no device-signed elements)
func encodeEmptyDeviceNameSpaces() -> CBOR {
    let emptyMap: CBOR = .map([:])
    let encodedEmptyMap = encodeCBOR(emptyMap)
    // #6.24(bstr .cbor {})
    return .tagged(CBOR.Tag(rawValue: 24), .byteString(encodedEmptyMap))
}

// MARK: - DeviceAuthenticationBytes (ISO 18013-5 §9.1.3.4)

/// Builds DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
///
///   DeviceAuthentication = [
///     "DeviceAuthentication",
///     SessionTranscript,       ; CborArray — inline, NOT bstr-wrapped
///     DocType,                 ; tstr
///     DeviceNameSpacesBytes    ; #6.24(bstr .cbor DeviceNameSpaces)
///   ]
///
/// - Parameters:
///   - sessionTranscript:      CBOR value from buildSessionTranscriptForOpenID4VP()
///   - docType:                e.g. "eu.europa.ec.eudi.pid.1"
///   - deviceNameSpacesBytes:  #6.24-tagged CBOR from encodeEmptyDeviceNameSpaces()
/// - Returns: CBOR-encoded bytes of the outer tag-24 structure (what gets signed)
func buildDeviceAuthenticationBytes(
    sessionTranscript: CBOR,
    docType: String,
    deviceNameSpacesBytes: CBOR    // must already be tag-24 wrapped
) -> [UInt8] {

    // Inner: DeviceAuthentication array
    let deviceAuthentication: CBOR = .array([
        .utf8String("DeviceAuthentication"),
        sessionTranscript,
        .utf8String(docType),
        deviceNameSpacesBytes
    ])

    let innerBytes = encodeCBOR(deviceAuthentication)

    // Outer: #6.24(bstr .cbor DeviceAuthentication)
    let tagged: CBOR = .tagged(CBOR.Tag(rawValue: 24), .byteString(innerBytes))
    return encodeCBOR(tagged)
}

// MARK: - COSE_Sign1 (ISO 18013-5 §9.1.3.6 / RFC 8152 §4.4)

/// Builds the protected header bytes: { 1: -7 } (alg: ES256)
func buildProtectedHeader() -> [UInt8] {
    // CBOR: map { 1 (uint) -> -7 (negint, stored as 6 in CBOR negint encoding) }
    let protectedMap: CBOR = .map([
        .unsignedInt(1): .negativeInt(6)   // -7 in CBOR negint = 6 (value = -1 - 6 = -7)
    ])
    return encodeCBOR(protectedMap)
}

/// Builds an untagged COSE_Sign1 for DeviceSignature per ISO 18013-5 §9.1.3.6.
///
/// Structure (RFC 8152 §4.4):
///   Sig_Structure = ["Signature1", protected, external_aad, payload]
///   COSE_Sign1    = [protected, unprotected, nil, signature]   (untagged, payload detached)
///
/// - Parameters:
///   - deviceAuthenticationBytes: Output of buildDeviceAuthenticationBytes() — the detached payload
///   - privateKey:                SecKey (EC P-256 private key) from Secure Enclave / Keychain
/// - Returns: CBOR value of the untagged COSE_Sign1 array, or nil on signing failure
func buildDeviceSignatureCoseSign1(
    deviceAuthenticationBytes: [UInt8],
    privateKey: SecKey
) -> CBOR? {

    let protectedHeaderBytes = buildProtectedHeader()

    // 1. Sig_Structure = ["Signature1", protected, external_aad, payload]
    let sigStructure: CBOR = .array([
        .utf8String("Signature1"),
        .byteString(protectedHeaderBytes),
        .byteString([]),                          // external_aad = h''
        .byteString(deviceAuthenticationBytes)    // detached payload
    ])

    let toBeSigned = encodeCBOR(sigStructure)

    // 2. Sign using ES256 (SHA256withECDSA) → DER signature → convert to P1363 (R|S, 64 bytes)
    guard let derSignature = signES256(privateKey: privateKey, data: Data(toBeSigned)) else {
        return nil
    }

    let signatureBytes: [UInt8]
    if derSignature.count != 64 {
        // DER-encoded: convert to P1363 (R|S)
        guard let p1363 = convertDerToP1363(der: derSignature, coordinateSize: 32) else {
            return nil
        }
        signatureBytes = p1363
    } else {
        signatureBytes = derSignature
    }

    // 3. COSE_Sign1 = [protected, unprotected, nil (detached), signature]
    let coseSign1: CBOR = .array([
        .byteString(protectedHeaderBytes),
        .map([:]),               // unprotected: empty map
        .null,                   // payload: detached
        .byteString(signatureBytes)
    ])

    return coseSign1
}

// MARK: - createDeviceSigned (top-level, mirrors Android createDeviceSigned())

/// Creates the full DeviceSigned structure to embed in a Document.
///
/// - Parameters:
///   - privateKey:      SecKey (P-256) for signing; pass nil to produce an unsigned stub
///   - sessionTranscript: CBOR from buildSessionTranscriptForOpenID4VP()
///   - docType:         Document type string, e.g. "eu.europa.ec.eudi.pid.1"
/// - Returns: SwiftCBOR CBOR value for the "deviceSigned" map
func createDeviceSignedCBOR(
    privateKey: SecKey?,
    sessionTranscript: CBOR,
    docType: String
) -> CBOR {

    // DeviceNameSpacesBytes = #6.24(bstr .cbor {})
    let emptyNamespaces = encodeEmptyDeviceNameSpaces()

    var deviceAuthMap: OrderedDictionary<CBOR, CBOR> = [:]

    if let key = privateKey {
        // Build DeviceAuthenticationBytes (the bytes that get signed)
        let deviceAuthBytes = buildDeviceAuthenticationBytes(
            sessionTranscript: sessionTranscript,
            docType: docType,
            deviceNameSpacesBytes: emptyNamespaces
        )

        // Build COSE_Sign1
        if let coseSign1 = buildDeviceSignatureCoseSign1(
            deviceAuthenticationBytes: deviceAuthBytes,
            privateKey: key
        ) {
            deviceAuthMap[.utf8String("deviceSignature")] = coseSign1
        }
    }
    // else: deviceAuth stays empty (unsigned stub)

    // deviceSigned = { "nameSpaces": emptyNamespaces, "deviceAuth": deviceAuthMap }
    var deviceSignedMap: OrderedDictionary<CBOR, CBOR> = [:]
    deviceSignedMap[.utf8String("nameSpaces")] = emptyNamespaces
    deviceSignedMap[.utf8String("deviceAuth")] = .map(deviceAuthMap)

    return .map(deviceSignedMap)
}

// MARK: - JWK Thumbprint (RFC 7638)

/// Computes the JWK Thumbprint as raw SHA-256 bytes from a SecKey (P-256 public key).
///
/// The canonical JSON members for P-256 are: { "crv", "kty", "x", "y" } (sorted).
/// This matches what the Python verifier does via `python-jose` / `jwcrypto`.
///
/// - Parameter publicKey: EC P-256 SecKey (public)
/// - Returns: Raw 32-byte SHA-256 thumbprint, or nil on failure
func computeJWKThumbprintBytes(publicKey: SecKey) -> [UInt8]? {
    var error: Unmanaged<CFError>?
    guard let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
        return nil
    }

    // EC uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes) — total 65 bytes
    guard keyData.count == 65, keyData[0] == 0x04 else { return nil }

    let xBytes = keyData[1...32]
    let yBytes = keyData[33...64]

    let xBase64 = Data(xBytes).base64URLEncodedString()
    let yBase64 = Data(yBytes).base64URLEncodedString()

    // RFC 7638 canonical JSON (keys sorted lexicographically: crv, kty, x, y)
    let canonicalJSON = """
    {"crv":"P-256","kty":"EC","x":"\(xBase64)","y":"\(yBase64)"}
    """

    guard let jsonBytes = canonicalJSON.data(using: .utf8) else { return nil }
    let digest = SHA256.hash(data: jsonBytes)
    return Array(digest)
}


func computeJwkThumbprintBytes(jwk: [String: Any]) -> [UInt8] {
    // 1. Canonicalize JWK per RFC 7638
    let canonicalJwk = canonicalizeJWK(jwk)

    // 2. Serialize canonical JSON (no whitespace, sorted keys)
    do {
        let jsonData = try JSONSerialization.data(
            withJSONObject: canonicalJwk,
            options: [.sortedKeys]
        )
        // 3. SHA-256 hash
        let hash = SHA256.hash(data: jsonData)

        // 4. Return raw bytes (32 bytes)
        return Array(hash)
    } catch {
        return []
    }
}

func canonicalizeJWK(_ jwk: [String: Any]) -> [String: String]? {
    guard let kty = jwk["kty"] as? String else {
        return nil
    }

    switch kty {
    case "EC":
        return extract(jwk, keys: ["crv", "kty", "x", "y"])

    case "RSA":
        return extract(jwk, keys: ["e", "kty", "n"])

    case "OKP": // e.g. Ed25519
        return extract(jwk, keys: ["crv", "kty", "x"])

    default:
        return nil
    }
}

func extract(_ jwk: [String: Any], keys: [String]) -> [String: String]? {
    var result: [String: String] = [:]

    for key in keys {
        guard let value = jwk[key] as? String else {
            return nil
        }
        result[key] = value
    }

    return result
}

// MARK: - Helpers

/// CBOR-encodes a single DataItem to bytes using SwiftCBOR.
func encodeCBOR(_ cbor: CBOR) -> [UInt8] {
    return cbor.encode()
}

/// Signs `data` with ES256 (SHA-256 + ECDSA) using a SecKey.
/// Returns the DER-encoded signature (standard Apple/Security framework output).
private func signES256(privateKey: SecKey, data: Data) -> [UInt8]? {
    var error: Unmanaged<CFError>?
    // SecKeyCreateSignature uses SHA256withECDSA and returns DER-encoded signature
    let attributes = SecKeyCopyAttributes(privateKey) as NSDictionary?
    print(attributes ?? [:])
    guard let signature = SecKeyCreateSignature(
        privateKey,
        .ecdsaSignatureMessageX962SHA256,
        data as CFData,
        &error
    ) as Data? else {
        return nil
    }
    return Array(signature)
}

/// Converts a DER-encoded ECDSA signature to the P1363 (R || S) format.
/// ES256 requires exactly 64 bytes (32 bytes each for R and S).
private func convertDerToP1363(der: [UInt8], coordinateSize: Int) -> [UInt8]? {
    var result = [UInt8](repeating: 0, count: coordinateSize * 2)
    var offset = 0

    guard der.count > 2, der[offset] == 0x30 else { return nil }
    offset += 1

    // Skip sequence length (handle both 1-byte and 2-byte length)
    if der[offset] == 0x81 {
        offset += 2
    } else {
        offset += 1
    }

    // Read R
    guard der[offset] == 0x02 else { return nil }
    offset += 1
    var rLen = Int(der[offset])
    offset += 1
    var rStart = offset
    if rLen > coordinateSize {
        rStart += (rLen - coordinateSize)
        rLen = coordinateSize
    }
    let rCopyLen = min(rLen, coordinateSize)
    result.replaceSubrange((coordinateSize - rCopyLen)..<coordinateSize,
                           with: der[rStart..<(rStart + rCopyLen)])
    offset += Int(der[offset - 1 - (rLen < Int(der[offset - 1]) ? 0 : 0)])

    // Recompute offset past R
    offset = rStart + (rLen < coordinateSize ? rLen : coordinateSize)
    if rLen < Int(der[2 + 1 + 1]) { // account for leading zero strip
        // already fine
    }

    // Re-parse cleanly to avoid off-by-one from above branching
    return parseDerToP1363(der: der, size: coordinateSize)
}

/// Clean DER → P1363 parser.
private func parseDerToP1363(der: [UInt8], size: Int) -> [UInt8]? {
    var result = [UInt8](repeating: 0, count: size * 2)
    var idx = 0

    guard idx < der.count, der[idx] == 0x30 else { return nil }
    idx += 1
    // Skip length
    if der[idx] & 0x80 != 0 {
        idx += 1 + Int(der[idx] & 0x7f)
    } else {
        idx += 1
    }

    func readInteger() -> [UInt8]? {
        guard idx < der.count, der[idx] == 0x02 else { return nil }
        idx += 1
        let len = Int(der[idx]); idx += 1
        let bytes = Array(der[idx..<(idx + len)]); idx += len
        // Strip leading zero padding
        if bytes.first == 0x00 { return Array(bytes.dropFirst()) }
        return bytes
    }

    guard let rBytes = readInteger(), let sBytes = readInteger() else { return nil }

    // Right-align within size bytes
    let rPad = size - rBytes.count
    let sPad = size - sBytes.count
    if rPad < 0 || sPad < 0 { return nil }

    for (i, b) in rBytes.enumerated() { result[rPad + i] = b }
    for (i, b) in sBytes.enumerated() { result[size + sPad + i] = b }

    return result
}
