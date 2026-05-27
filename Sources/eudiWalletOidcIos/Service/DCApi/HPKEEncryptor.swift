import Foundation
import CryptoKit

@available(iOS 17.0, *)
public struct HPKEEncryptionResult {
    public let encapsulatedKey: Data
    public let cipherText: Data
}

@available(iOS 17.0, *)
public class HPKEEncryptor {

    /// Encrypts the DeviceResponse bytes using HPKE.
    ///
    /// Cipher suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
    ///
    /// - Parameters:
    ///   - plaintext: CBOR-encoded DeviceResponse bytes
    ///   - recipientPublicKey: The recipient's P-256 public key from EncryptionInfo
    ///   - sessionTranscriptBytes: CBOR-encoded SessionTranscript (HPKE info parameter)
    /// - Returns: HPKEEncryptionResult with encapsulated key and ciphertext
    public static func encrypt(
        plaintext: Data,
        recipientPublicKey: ParsedCOSEKey,
        sessionTranscriptBytes: [UInt8]
    ) throws -> HPKEEncryptionResult {
        let cipherSuite = HPKE.Ciphersuite(
            kem: .P256_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_128
        )

        let pubKeyData = recipientPublicKey.toUncompressedPoint()
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: pubKeyData)

        var sender = try HPKE.Sender(
            recipientKey: publicKey,
            ciphersuite: cipherSuite,
            info: Data(sessionTranscriptBytes)
        )

        let cipherText = try sender.seal(plaintext, authenticating: Data())
        let encapsulatedKey = sender.encapsulatedKey

        return HPKEEncryptionResult(
            encapsulatedKey: encapsulatedKey,
            cipherText: cipherText
        )
    }
}
