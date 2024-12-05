//
//  ClientIDSchemeVerification.swift
//  dataWallet
//
//  Created by iGrant on 11/11/24.
//
import Foundation
import ASN1Decoder
import Security
public class X509SanRequestVerifier {
    
    public static let shared = X509SanRequestVerifier()
    public init() {}
    
    func extractX5cFromJWT(jwt: String) -> [String]? {
            let segments = jwt.split(separator: ".")
            guard segments.count == 3 else {
                print("Invalid JWT format")
                return nil
            }
            
            let headerSegment = "\(segments[0])"
        let header = headerSegment.decodeBase64() ?? ""
            guard let headerData = header.data(using: .utf8),
                  let headerDict = try? JSONSerialization.jsonObject(with: headerData, options: []) as? [String: Any],
                  let x5cChain = headerDict["x5c"] as? [String] else {
                print("Failed to decode JWT header or x5c not found")
                return nil
            }
            
            return x5cChain
        }
    
    func validateClientIDInCertificate(x5cChain: [String], clientID: String) -> Bool {
        guard let leafCertData = Data(base64Encoded: x5cChain.first ?? "") else {
            return false
        }
        
        // Create SecCertificate from leaf certificate data
        guard let certificate = SecCertificateCreateWithData(nil, leafCertData as CFData) else {
            print("Invalid certificate data")
            return false
        }
        let dnsNames = extractDNSNamesFromCertificate(certificate: certificate)
        // Check if clientID matches any DNS name in SAN
        return dnsNames.contains(clientID)
    }
    
    func extractDNSNamesFromCertificate(certificate: SecCertificate) -> [String] {
        var dnsNames = [String]()
        
        let certData = SecCertificateCopyData(certificate) as Data
        do {
            let asn1Data = try ASN1DERDecoder.decode(data: certData)
            for element in asn1Data {
                if let sequence = element as? ASN1Object {
                    dnsNames = extractSubjectAltNames(from: sequence)
                }
            }
            return dnsNames
        } catch {
            print("error")
        }
        return dnsNames
    }
    
    func extractSubjectAltNames(from asn1Object: ASN1Object) -> [String] {
        var altNames = [String]()
        
        guard let subjectAltNameObj = asn1Object.findOid(.subjectAltName), let parentStructure = subjectAltNameObj.parent else {
            return altNames
        }
//        let parentSubObjects = parentStructure.sub as? [ASN1Object]
//        let octetStringObject1 = parentSubObjects?.first(where: { $0.identifier?.tagNumber() == .octetString })
//        let octetStringSubObjects1 = octetStringObject1?.sub as? [ASN1Object]
//        print("")
        var subArray: [ASN1Object] = []
        for index in 0...parentStructure.subCount() {
            if let subObject = parentStructure.sub(index) {
                subArray.append(subObject)
            }
        }
        if let octetStringObject = subArray.first(where: { $0.identifier?.tagNumber() == .octetString }) {
            var octetSubArray: [ASN1Object] = []
            for index in 0...octetStringObject.subCount() {
                if let subObject = octetStringObject.sub(index) {
                    octetSubArray.append(subObject)
                }
            }
            if let altNameSequence = octetSubArray.first(where: { $0.identifier?.tagNumber() == .sequence }) {
                var altNameSequenceArray: [ASN1Object] = []
                for index in 0...altNameSequence.subCount() {
                    if let subObject = altNameSequence.sub(index) {
                        altNameSequenceArray.append(subObject)
                    }
                }
                for altNameObj in altNameSequenceArray {
                    if let altNameString = altNameObj.asString {
                        altNames.append(altNameString)
                    } else if let altNameValue = altNameObj.value as? String {
                        altNames.append(altNameValue)
                    }
                }
            }
        }
        
        return altNames
    }
    
    func validateSignatureWithCertificate(jwt: String, x5cChain: [String]) -> Bool {
        guard let leafCertData = Data(base64Encoded: x5cChain.first ?? ""),
              let certificate = SecCertificateCreateWithData(nil, leafCertData as CFData) else {
            print("Failed to create certificate from leaf certificate data")
            return false
        }
        
        guard let publicKey = SecCertificateCopyKey(certificate) else {
            print("Unable to extract public key from certificate")
            return false
        }
        
        let segments = jwt.split(separator: ".")
        guard segments.count == 3 else {
            print("Invalid JWT format")
            return false
        }
        
        let signedData = segments[0] + "." + segments[1]
        var sigatureData: String = ""
        if segments[2].contains("~") {
            let splitData = segments[2].split(separator: "~")
            sigatureData = String(splitData[0])
        } else {
            sigatureData = String(segments[2])
        }
        let b64 = base64UrlToBase64(sigatureData)
        guard let rawSignature = Data(base64Encoded: b64) else {
            print("Failed to decode JWT signature")
            return false
        }
        guard let jsonString = "\(segments[0])".decodeBase64(),
              let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString), let alg = jsonObject["alg"] as? String, let algorithm = mapJWTAlgToSecKeyAlgorithm(alg: alg) else { return false }
        let signature: Data
        if alg.starts(with: "ES"), let convertedSignature = convertRawSignatureToASN1DER(rawSignature) {
            signature = convertedSignature
        } else {
            signature = rawSignature
        }
        
        return verifySignature(publicKey: publicKey, data: String(signedData), signature: signature, algorithm: algorithm)
    }
    
    func base64UrlToBase64(_ base64Url: String) -> String {
        var base64 = base64Url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        
        return base64
    }
    //  perform the actual signature verification
    func verifySignature(publicKey: SecKey, data: String, signature: Data, algorithm: SecKeyAlgorithm) -> Bool {
        guard let dataToVerify = data.data(using: .utf8) else {
            print("Failed to convert data to verify to Data")
            return false
        }
        
        // Check if the algorithm is supported for the given key
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            print("Algorithm not supported by public key")
            return false
        }
        
        // Perform the verification
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(publicKey, algorithm, dataToVerify as CFData, signature as CFData, &error)
        
        if let error = error {
            print("Signature verification failed with error: \(error.takeRetainedValue())")
            return false
        }
        
        return result
    }
    
    func validateTrustChain(x5cChain: [String]) -> Bool {
        var certificates = [SecCertificate]()
        for certBase64 in x5cChain {
            if let certData = Data(base64Encoded: certBase64),
               let certificate = SecCertificateCreateWithData(nil, certData as CFData) {
                certificates.append(certificate)
            } else {
                print("Invalid certificate in chain")
                return false
            }
        }
        
        guard !certificates.isEmpty else { return false }
        
        // Create a trust object with a custom policy
        var secTrust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        let status = SecTrustCreateWithCertificates(certificates as CFArray, policy, &secTrust)
        guard status == errSecSuccess, let trust = secTrust else {
            print("Failed to create trust object")
            return false
        }
        // Optionally add custom anchors to the trust evaluation
        SecTrustSetAnchorCertificates(trust, certificates as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, false)
        // Evaluate the trust chain without requiring a root in the system’s trust store
        var error: CFError?
        let isValid = SecTrustEvaluateWithError(trust, &error)
        if let error = error {
            print("Trust chain validation failed with error: \(error)")
        }
        return isValid
    }
    
    func mapJWTAlgToSecKeyAlgorithm(alg: String) -> SecKeyAlgorithm? {
        switch alg {
        case "RS256":
            return .rsaSignatureMessagePKCS1v15SHA256
        case "RS384":
            return .rsaSignatureMessagePKCS1v15SHA384
        case "RS512":
            return .rsaSignatureMessagePKCS1v15SHA512
        case "ES256":
            return .ecdsaSignatureMessageX962SHA256
        case "ES384":
            return .ecdsaSignatureMessageX962SHA384
        case "ES512":
            return .ecdsaSignatureMessageX962SHA512
        default:
            return nil
        }
    }
    
    func convertRawSignatureToASN1DER(_ rawSignature: Data) -> Data? {
        let halfLength = rawSignature.count / 2
        let r = rawSignature.prefix(halfLength)
        let s = rawSignature.suffix(halfLength)
        func asn1Length(_ length: Int) -> Data {
            if length < 128 {
                return Data([UInt8(length)])
            }
            var lengthBytes = withUnsafeBytes(of: length.bigEndian, Array.init)
            while lengthBytes.first == 0 {
                lengthBytes.removeFirst()
            }
            return Data([0x80 | UInt8(lengthBytes.count)] + lengthBytes)
        }
        func asn1Integer(_ data: Data) -> Data {
            var bytes = Array(data)
            // Add a leading zero if the MSB is set (to avoid it being interpreted as negative)
            if let first = bytes.first, first & 0x80 != 0 {
                bytes.insert(0, at: 0)
            }
            return Data([0x02, UInt8(bytes.count)] + bytes)
        }
        let asn1R = asn1Integer(r)
        let asn1S = asn1Integer(s)
        let asn1Sequence = Data([0x30]) + asn1Length(asn1R.count + asn1S.count) + asn1R + asn1S
        return asn1Sequence
    }
    
}
