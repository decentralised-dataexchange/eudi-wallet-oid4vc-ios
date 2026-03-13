//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 08/01/26.
//

import Foundation
import SwiftCBOR

public class MdocSignatureValidationHelper {
    public init() {}
    
    public func verifyMdocIssuerSignatureForX509(issuerAuth: CBOR) -> Bool {
        
        //  Extract COSE parts
        guard let coseParts = try extractCoseSign1Parts(from: issuerAuth) else {
            return false
        }
        
        //  Extract x5c (your existing function)
        guard let x5cChain =
                FilterCredentialService()
            .extractX5cFromIssuerAuth1(issuerAuth: issuerAuth)
        else {
            return false
        }
        
        //  Convert & validate certificates
        let certificates = try certificatesFromX5C(x5cChain)
        
        //  Extract public key from leaf cert
        guard let publicKey = SecCertificateCopyKey(certificates[0]) else {
            return false
        }
        
        //  Build Sig_structure
        let sigStructure = buildCoseSigStructure(
            protectedHeaders: coseParts.protectedHeaders,
            payload: coseParts.payload
        )
        
        //  Verify signature
        return try verifyCoseSignature(
            publicKey: publicKey,
            sigStructure: sigStructure,
            signature: coseParts.signature
        )
    }
    
    func extractJWKFromIssuerAuth(issuerAuth: CBOR) -> [String: Any]? {
    guard case let CBOR.array(coseArray) = issuerAuth,
          coseArray.count >= 2 else {
        return nil
    }
    
    if case let CBOR.map(unprotectedHeaders) = coseArray[1] {
        let jwkCBOR = unprotectedHeaders[CBOR.utf8String("jwk")]
            ?? unprotectedHeaders[CBOR.negativeInt(1)]
        
        if let jwkCBOR = jwkCBOR, let jwk = extractJWKFromCBOR(jwkCBOR) {
            return jwk
        }
    }
    
    if case let CBOR.byteString(protectedBytes) = coseArray[0] {
        let data = Data(protectedBytes)
        if let protectedCBOR = try? CBOR.decode(Array(data)),
           case let CBOR.map(protectedHeaders) = protectedCBOR {
            
            let jwkCBOR = protectedHeaders[CBOR.utf8String("jwk")]
                ?? protectedHeaders[CBOR.negativeInt(1)]
            
            if let jwkCBOR = jwkCBOR, let jwk = extractJWKFromCBOR(jwkCBOR) {
                return jwk
            }
        }
    }
    
    return nil
}

    // MARK: - Private CBOR JWK Parser
    private func extractJWKFromCBOR(_ cbor: CBOR) -> [String: Any]? {
        switch cbor {
        // Case 1: JWK encoded as a native CBOR map
        case .map(let cborMap):
            var jwkDict: [String: Any] = [:]
            for (key, value) in cborMap {
                guard let keyString = cborKeyToString(key) else { continue }
                jwkDict[keyString] = cborValueToSwift(value)
            }
            return jwkDict.isEmpty ? nil : jwkDict
            
        // Case 2: JWK embedded as raw JSON bytes
        case .byteString(let bytes):
            guard let parsed = try? JSONSerialization.jsonObject(
                with: Data(bytes)
            ) as? [String: Any] else {
                return nil
            }
            return parsed
            
        // Case 3: JWK embedded as a JSON string
        case .utf8String(let str):
            guard let data = str.data(using: .utf8),
                  let parsed = try? JSONSerialization.jsonObject(
                    with: data
                  ) as? [String: Any] else {
                return nil
            }
            return parsed
            
        default:
            return nil
        }
    }
    
    
    public  func verifyCoseSignature(
        publicKey: SecKey,
        sigStructure: Data,
        signature: Data
    ) -> Bool {
        
        guard let derSignature = coseSignatureToDER(signature) else {
            return false
        }
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        
        return SecKeyVerifySignature(
            publicKey,
            algorithm,
            sigStructure as CFData,
            derSignature as CFData,
            nil
        )
    }
    
    public func coseSignatureToDER(_ coseSignature: Data) -> Data? {
        guard coseSignature.count == 64 else { return nil }
        
        let r = coseSignature.prefix(32)
        let s = coseSignature.suffix(32)
        
        func derInteger(_ raw: Data) -> Data {
            var bytes = [UInt8](raw)
            
            while bytes.first == 0 && bytes.count > 1 {
                bytes.removeFirst()
            }
            
            if bytes.first! & 0x80 != 0 {
                bytes.insert(0x00, at: 0)
            }
            
            return Data([0x02, UInt8(bytes.count)]) + Data(bytes)
        }
        
        let rDER = derInteger(r)
        let sDER = derInteger(s)
        
        let sequenceLen = rDER.count + sDER.count
        return Data([0x30, UInt8(sequenceLen)]) + rDER + sDER
    }
    
    public func certificatesFromX5C(_ x5c: [String]) -> [SecCertificate] {
        
        let certs = x5c.compactMap { base64 -> SecCertificate? in
            guard let data = Data(base64Encoded: base64) else { return nil }
            return SecCertificateCreateWithData(nil, data as CFData)
        }
        
        guard !certs.isEmpty else {
            return []
        }
        
        return certs
    }

    private func cborKeyToString(_ cbor: CBOR) -> String? {
        switch cbor {
        case .utf8String(let str): return str
        case .unsignedInt(let i):  return String(i)
        case .negativeInt(let i):  return String(-1 - Int(i))
        default:                   return nil
        }
    }

    private func cborValueToSwift(_ cbor: CBOR) -> Any {
        switch cbor {
        case .utf8String(let str):   return str
        case .unsignedInt(let i):    return i
        case .negativeInt(let i):    return -1 - Int(i)
        case .boolean(let b):        return b
        case .float(let f):          return f
        case .double(let d):         return d
        case .byteString(let bytes): return Data(bytes).base64URLEncodedString()
        case .array(let arr):        return arr.map { cborValueToSwift($0) }
        case .map(let map):
            var dict: [String: Any] = [:]
            for (k, v) in map {
                if let key = cborKeyToString(k) {
                    dict[key] = cborValueToSwift(v)
                }
            }
            return dict
        default: return "\(cbor)"
        }
    }
    
    public func buildCoseSigStructure(
        protectedHeaders: Data,
        payload: Data
    ) -> Data {
        
        let sigStructure: [CBOR] = [
            .utf8String("Signature1"),
            .byteString([UInt8](protectedHeaders)),
            .byteString([]),
            .byteString([UInt8](payload))
        ]
        
        let encoded: [UInt8] = CBOR.encode(.array(sigStructure))(options: CBOROptions())
        
        return Data(encoded)
    }
    
    public func getCOSEAlgorithm(from base64CBOR: String) throws -> String {
        guard let data = Data(base64URLEncoded: base64CBOR) else {
            throw NSError(domain: "InvalidBase64", code: -1)
        }
        
        guard let cbor = try CBOR.decode([UInt8](data)) else {
            throw NSError(domain: "CBORDecodeFailed", code: -10)
        }
        
        let coseArray: [CBOR]
        
        switch cbor {
        case .array(let items):
            // Direct COSE_Sign1
            coseArray = items
            
        case .map(let map):
            // Wrapped COSE_Sign1 → find the array
            guard let (_, value) = map.first(where: { (_, value) in
                if case .array = value { return true }
                return false
            }),
                  case let CBOR.array(items) = value else {
                throw NSError(domain: "COSEArrayNotFound", code: -20)
            }
            coseArray = items
            
        default:
            throw NSError(domain: "InvalidCOSEStructure", code: -21)
        }
        
        guard coseArray.count >= 1 else {
            throw NSError(domain: "InvalidCOSE", code: -2)
        }
        
        guard case let CBOR.byteString(protectedHeaderBytes) = coseArray[0] else {
            throw NSError(domain: "MissingProtectedHeader", code: -3)
        }
        
        guard let protectedHeader = try CBOR.decode(protectedHeaderBytes) else {
            throw NSError(domain: "InvalidCOSE", code: -2)
        }
        
        guard case let CBOR.map(headerMap) = protectedHeader else {
            throw NSError(domain: "InvalidProtectedHeader", code: -4)
        }
        
        //Extract alg (key = 1)
        let algKey = CBOR.unsignedInt(1)
        
        guard let algValue = headerMap[algKey],
              case let CBOR.negativeInt(algRaw) = algValue else {
            throw NSError(domain: "AlgorithmNotFound", code: -5)
        }
        
        let coseAlg = -Int(algRaw) - 1
        
        guard let algorithm = COSEAlgorithm(rawValue: coseAlg) else {
            return "Unknown COSE algorithm (\(coseAlg))"
        }
        
        return algorithm.name
    }
    
    public func extractCoseSign1Parts(from issuerAuth: CBOR) -> CoseSign1? {
        
        guard case let CBOR.array(items) = issuerAuth,
              items.count == 4 else {
            return nil
        }
        
        guard case let CBOR.byteString(protectedBytes) = items[0],
              case let CBOR.byteString(payloadBytes)   = items[2],
              case let CBOR.byteString(signatureBytes) = items[3] else {
            return nil
        }
        
        return CoseSign1(
            protectedHeaders: Data(protectedBytes),
            payload: Data(payloadBytes),
            signature: Data(signatureBytes)
        )
    }
    
    public func validateSignatureForMdoc(jwk: [Any], issuerAuth: CBOR, cborString: String) -> (Bool?, Bool) {
        var validationResults: [Bool] = []
        var isX5cSigNotValid: Bool = false
        for data in jwk {
            if let item = data as? [String] {
                let isValid = verifyMdocIssuerSignatureForX509(issuerAuth: issuerAuth)
                validationResults.append(isValid)
                if !isValid {
                    isX5cSigNotValid = true
                }
            } else {
                var publicKey: Any?
                var alg: String = ""
                do {
                    alg = try getCOSEAlgorithm(from: cborString)
                } catch {
                   
                }
                if alg == "EdDSA" {
                    guard let jwkData = data as? [String: Any], let crv = jwkData["crv"] as? String, crv == "Ed25519" else {
                        validationResults.append(false)
                        continue
                    }
                    publicKey = SignatureValidator.extractPublicKey(from: jwkData, crv: crv)
                } else {
                    guard let jwkData = data as? [String: Any], let crv = jwkData["crv"] as? String else {
                        validationResults.append(false)
                        continue
                    }
                    let algToCrvMap: [String: String] = [
                        "ES256": "P-256",
                        "ES384": "P-384",
                        "ES512": "P-521"
                    ]
                    if let expectedCrv = algToCrvMap[alg], expectedCrv != crv {
                        validationResults.append(false)
                        continue
                    }
                    publicKey = SignatureValidator.extractPublicKey(from: data as? [String: Any] ?? [:], crv: crv)
                }
                if publicKey == nil { validationResults.append(false)
                    continue }
                guard let coseParts = try extractCoseSign1Parts(from: issuerAuth) else {
                    return (false, false)
                }
                let sigStructure = buildCoseSigStructure(
                    protectedHeaders: coseParts.protectedHeaders,
                    payload: coseParts.payload
                )
                let isVerified = SignatureValidator.verifySignature(signature: coseParts.signature, for: sigStructure, using: publicKey)
                
                validationResults.append(isVerified)

            }
        }
        return (validationResults.contains(true), isX5cSigNotValid)
    }
    
}

public struct CoseSign1 {
    let protectedHeaders: Data
    let payload: Data
    let signature: Data
}

public enum COSEAlgorithm: Int {
    case es256 = -7
    case eddsa = -8
    case es384 = -35
    case es512 = -36

    var name: String {
        switch self {
        case .es256: return "ES256"
        case .eddsa: return "EdDSA"
        case .es384: return "ES384"
        case .es512: return "ES512"
        }
    }
}
