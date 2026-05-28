import Foundation
import SwiftCBOR
import OrderedCollections

@available(iOS 17.0, *)
class DCAPIResponseBuilder {

    /// Builds the raw encrypted response CBOR bytes.
    ///
    /// Encrypted response CBOR:
    ///   ["dcapi", {"enc": <encapsulatedKey bytes>, "cipherText": <cipherText bytes>}]
    ///
    /// This is what the iOS DC API (`ISO18013MobileDocumentResponse.responseData`)
    /// expects — the platform performs the protocol/data envelope wrapping itself.
    static func buildEncryptedResponseBytes(
        encryptionResult: HPKEEncryptionResult
    ) -> Data {
        let encryptedResponseMap: OrderedDictionary<CBOR, CBOR> = [
            .utf8String("enc"): .byteString(Array(encryptionResult.encapsulatedKey)),
            .utf8String("cipherText"): .byteString(Array(encryptionResult.cipherText))
        ]

        let encryptedResponseCBOR: CBOR = .array([
            .utf8String("dcapi"),
            .map(encryptedResponseMap)
        ])

        return Data(encodeCBOR(encryptedResponseCBOR))
    }

    /// Builds the encrypted response CBOR and wraps it in the DC API JSON format.
    ///
    /// Encrypted response CBOR:
    ///   ["dcapi", {"enc": <encapsulatedKey bytes>, "cipherText": <cipherText bytes>}]
    ///
    /// Response JSON:
    ///   {"protocol": "org-iso-mdoc", "data": {"response": "<base64url>"}}
    static func buildResponseJSON(
        encryptionResult: HPKEEncryptionResult
    ) -> [String: Any]? {
        let responseBase64 = buildEncryptedResponseBytes(
            encryptionResult: encryptionResult
        ).base64URLEncodedString()

        let responseJSON: [String: Any] = [
            "protocol": "org-iso-mdoc",
            "data": [
                "response": responseBase64
            ]
        ]

        return responseJSON
    }

    /// Encodes the full response as a JSON string.
    static func buildResponseJSONString(
        encryptionResult: HPKEEncryptionResult
    ) -> String? {
        guard let responseDict = buildResponseJSON(encryptionResult: encryptionResult) else {
            return nil
        }
        guard let jsonData = try? JSONSerialization.data(
            withJSONObject: responseDict,
            options: [.sortedKeys]
        ) else {
            return nil
        }
        return String(data: jsonData, encoding: .utf8)
    }
}
