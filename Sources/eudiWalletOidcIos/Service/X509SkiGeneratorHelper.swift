//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 02/09/25.
//

import Foundation
import Security
import CryptoKit
import ASN1Decoder

public class X509SkiGeneratorHelper {
    
    /// Parses a Base64-encoded X.509 certificate string and returns a SecCertificate object.
    public static func parseCertificateFromBase64(_ base64Cert: String) -> SecCertificate? {
        guard let certData = Data(base64Encoded: base64Cert) else { return nil }
        return SecCertificateCreateWithData(nil, certData as CFData)
    }
    
    /// Generates the Subject Key Identifier (SKI) string from the certificate.
    /// Tries to use extension 2.5.29.14 (SKI); falls back to SHA-1 hash of public key if not present.
    public static func generateSkiString(cert: SecCertificate) -> String? {
        // Try to extract SKI (OID: 2.5.29.14)
        if let extData = getExtensionFromCertificate(cert: cert, oid: "2.5.29.14"),
           let skiBytes = extractOctetString(from: extData) {
            return skiBytes.map { String(format: "%02X", $0) }.joined()
        }
        
        // Fallback: SHA-1 of public key
        guard let publicKey = extractPublicKey(cert: cert),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }
        
        let sha1Hash = Insecure.SHA1.hash(data: publicKeyData)
        return sha1Hash.map { String(format: "%02X", $0) }.joined()
    }
    
    public static func extractPublicKeyBase64(from cert: SecCertificate) -> String? {
        guard let publicKey = extractPublicKey(cert: cert),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }
        return publicKeyData.base64EncodedString()
    }
    
    public static func extractBase64PublicKey(from x5cBase64: String) -> String? {
        // Step 1: Decode base64 to get DER bytes
        guard let certData = Data(base64Encoded: x5cBase64) else {
            print("Invalid base64 x5c input")
            return nil
        }

        
        // Step 2: Create X.509 certificate
        guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
            print("Failed to create certificate from data")
            return nil
        }

        // Step 3: Extract public key
        guard let publicKey = SecCertificateCopyKey(certificate) else {
            print("Failed to extract public key")
            return nil
        }

        // Step 4: Export public key as DER-encoded (SPKI format)
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            print("Failed to export public key: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")")
            return nil
        }
        
        let ecP256Header: [UInt8] = [
               0x30, 0x59, // SEQUENCE (length 89)
               0x30, 0x13, // SEQUENCE (length 19)
               0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID: ecPublicKey
               0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID: P-256
               0x03, 0x42, 0x00 // BIT STRING (66 bytes, 0 unused bits)
           ]
        var spki = Data(ecP256Header)
        spki.append(publicKeyData)

        // Step 5: Return Base64 string of public key
        return spki.base64EncodedString()
    }
    
    public static func generateSKI(from x5cCertificateBase64: String) -> String? {
        guard let certData = Data(base64Encoded: x5cCertificateBase64) else {
            print("Invalid base64 x5c certificate")
            return nil
        }

        guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
            print("Unable to create certificate")
            return nil
        }

        guard let publicKey = SecCertificateCopyKey(certificate) else {
            print("Unable to extract public key")
            return nil
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            print("Failed to export public key: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")")
            return nil
        }

        let skiHash = Insecure.SHA1.hash(data: publicKeyData)
        let hexString = skiHash.map { String(format: "%02X", $0) }.joined()
        return hexString
    }
    
    
    
    /// Extracts an extension from the certificate using the given OID.
    private static func getExtensionFromCertificate(cert: SecCertificate, oid: String) -> Data? {
//        guard let values = SecCertificateCopyValues(cert, [oid as CFString] as CFArray, nil) as? [CFString: Any],
//              let extDict = values[oid as CFString] as? [CFString: Any],
//              let data = extDict[kSecPropertyKeyValue] else {
//            return nil
//        }
//
//        // Sometimes SKI value is a hex string, sometimes raw bytes
//        if let hexString = data as? String,
//           let bytes = Data(hexString) {
//            return bytes
//        } else if let dataBytes = data as? Data {
//            return dataBytes
//        }

        return nil
    }
    
    /// Extracts the inner octet string from ASN.1 encoded data
    private static func extractOctetString(from data: Data) -> Data? {
        // Basic ASN.1 DER structure: [tag, length, value]
        guard data.count >= 2 else { return nil }

        var index = 0
        let tag = data[index]
        index += 1

        let length = Int(data[index])
        index += 1

        guard index + length <= data.count else { return nil }

        let inner = data[index..<(index + length)]
        return Data(inner)
    }

    /// Extracts the public key from a certificate
    private static func extractPublicKey(cert: SecCertificate) -> SecKey? {
        var trust: SecTrust?
        SecTrustCreateWithCertificates(cert, SecPolicyCreateBasicX509(), &trust)
        return trust.flatMap { SecTrustCopyKey($0) }
        
    }
}
