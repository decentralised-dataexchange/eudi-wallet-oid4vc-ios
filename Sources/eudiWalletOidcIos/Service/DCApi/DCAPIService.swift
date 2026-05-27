import Foundation
import SwiftCBOR
import OrderedCollections
import CryptoKit
import Security

@available(iOS 17.0, *)
public class DCAPIService {

    private let mdocBuilder = MDocVpTokenBuilder()

    public init() {}

    /// Main entry point for ISO 18013-7 Annex C non-OpenID DC API flow.
    ///
    /// - Parameters:
    ///   - requestJSON: The DC API request JSON string.
    ///     Expected: `{"requests":[{"protocol":"org-iso-mdoc","data":{"deviceRequest":"<b64url>","encryptionInfo":"<b64url>"}}]}`
    ///   - origin: The calling website/app origin (e.g., "https://example.com")
    ///   - credentials: Array of base64url-encoded mDOC CBOR credentials
    ///   - keyHandler: SecureKeyProtocol for device authentication signing
    /// - Returns: Result with response JSON string or DCAPIError
    public func processRequest(
        requestJSON: String,
        origin: String,
        credentials: [String],
        keyHandler: SecureKeyProtocol
    ) async -> Result<String, DCAPIError> {
        do {
            // 1. Parse the request JSON
            let (deviceRequestB64, encryptionInfoB64) = try parseRequestJSON(requestJSON)

            // 2. Parse the DeviceRequest CBOR
            let deviceRequest = try DeviceRequestParser.parse(base64url: deviceRequestB64)

            // 3. Parse the EncryptionInfo CBOR
            let encryptionInfo = try EncryptionInfoParser.parse(base64url: encryptionInfoB64)

            // 4. Build the DC API session transcript
            let (sessionTranscriptCBOR, sessionTranscriptBytes) = buildSessionTranscriptForDCAPI(
                encryptionInfoBase64: encryptionInfoB64,
                origin: origin
            )

            // 5. Build documents for each DocRequest
            var documents: [Document] = []
            for docRequest in deviceRequest.docRequests {
                guard let document = try buildDocument(
                    docRequest: docRequest,
                    credentials: credentials,
                    sessionTranscript: sessionTranscriptCBOR,
                    keyHandler: keyHandler
                ) else {
                    continue
                }
                documents.append(document)
            }

            if documents.isEmpty {
                let requestedTypes = deviceRequest.docRequests.map { $0.docType }.joined(separator: ", ")
                return .failure(.noMatchingCredential(docType: requestedTypes))
            }

            // 6. Build DeviceResponse and CBOR-encode
            let deviceResponse = DeviceResponse(version: "1.0", documents: documents, status: 0)
            let deviceResponseCBOR = deviceResponse.toCBOR()
            let deviceResponseBytes = encodeCBOR(deviceResponseCBOR)

            // 7. HPKE encrypt
            let encryptionResult = try HPKEEncryptor.encrypt(
                plaintext: Data(deviceResponseBytes),
                recipientPublicKey: encryptionInfo.recipientPublicKey,
                sessionTranscriptBytes: sessionTranscriptBytes
            )

            // 8. Build response JSON
            guard let responseString = DCAPIResponseBuilder.buildResponseJSONString(
                encryptionResult: encryptionResult
            ) else {
                return .failure(.cborEncodingFailed)
            }

            return .success(responseString)

        } catch let error as DCAPIError {
            return .failure(error)
        } catch {
            return .failure(.invalidRequestJSON(error.localizedDescription))
        }
    }

    // MARK: - Private

    private func parseRequestJSON(_ json: String) throws -> (deviceRequest: String, encryptionInfo: String) {
        guard let data = json.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw DCAPIError.invalidRequestJSON("Failed to parse JSON")
        }

        // Support both {"requests":[...]} and direct {"protocol":...,"data":{...}} formats
        let firstRequest: [String: Any]
        if let requests = parsed["requests"] as? [[String: Any]], let first = requests.first {
            firstRequest = first
        } else if parsed["protocol"] != nil {
            firstRequest = parsed
        } else {
            throw DCAPIError.invalidRequestJSON("Missing 'requests' array or 'protocol' field")
        }

        guard let protocol_ = firstRequest["protocol"] as? String else {
            throw DCAPIError.invalidRequestJSON("Missing 'protocol'")
        }
        guard protocol_ == "org-iso-mdoc" else {
            throw DCAPIError.unsupportedProtocol(protocol_)
        }

        guard let requestData = firstRequest["data"] as? [String: Any],
              let deviceRequestB64 = requestData["deviceRequest"] as? String,
              let encryptionInfoB64 = requestData["encryptionInfo"] as? String else {
            throw DCAPIError.invalidRequestJSON("Missing 'data.deviceRequest' or 'data.encryptionInfo'")
        }

        return (deviceRequestB64, encryptionInfoB64)
    }

    private func buildDocument(
        docRequest: ParsedDocRequest,
        credentials: [String],
        sessionTranscript: CBOR,
        keyHandler: SecureKeyProtocol
    ) throws -> Document? {
        // Find a matching credential by docType
        var matchedCredential: String?
        for credential in credentials {
            guard !credential.contains(".") else { continue }
            guard let issuerAuth = mdocBuilder.getIssuerAuth(credential: credential),
                  let credDocType = mdocBuilder.getDocTypeFromIssuerAuth(cborData: issuerAuth),
                  credDocType == docRequest.docType else { continue }
            matchedCredential = credential
            break
        }

        guard let credential = matchedCredential else {
            return nil
        }

        guard let issuerAuth = mdocBuilder.getIssuerAuth(credential: credential) else {
            return nil
        }

        guard let nameSpaces = mdocBuilder.getNameSpaces(credential: credential, query: nil) else {
            return nil
        }

        // Filter nameSpaces by the DeviceRequest's requested elements
        let filteredNameSpaces = filterNameSpacesByDeviceRequest(
            nameSpacesValue: nameSpaces,
            requestedNamespaces: docRequest.requestedNamespaces
        )

        // Build DeviceSigned
        let _ = keyHandler.generateSecureKey()
        let privateKey = keyHandler.getSecurePrivateKey()
        let deviceSigned = buildDeviceSignedForDCAPI(
            privateKey: privateKey,
            sessionTranscript: sessionTranscript,
            docType: docRequest.docType
        )

        return Document(
            docType: docRequest.docType,
            issuerSigned: IssuerSigned(
                nameSpaces: filteredNameSpaces ?? nameSpaces,
                issuerAuth: issuerAuth
            ),
            deviceSigned: deviceSigned
        )
    }

    private func buildDeviceSignedForDCAPI(
        privateKey: SecKey?,
        sessionTranscript: CBOR,
        docType: String
    ) -> DeviceSigned? {
        let emptyNamespaces = encodeEmptyDeviceNameSpaces()
        var deviceAuthMap: OrderedDictionary<CBOR, CBOR> = [:]

        if let key = privateKey {
            let deviceAuthBytes = buildDeviceAuthenticationBytes(
                sessionTranscript: sessionTranscript,
                docType: docType,
                deviceNameSpacesBytes: emptyNamespaces
            )
            if let coseSign1 = buildDeviceSignatureCoseSign1(
                deviceAuthenticationBytes: deviceAuthBytes,
                privateKey: key
            ) {
                deviceAuthMap[.utf8String("deviceSignature")] = coseSign1
            }
        }

        return DeviceSigned(
            nameSpaces: emptyNamespaces,
            deviceAuth: .map(deviceAuthMap)
        )
    }

    /// Filters nameSpaces CBOR based on the DeviceRequest's requested namespaces and elements.
    /// Unlike the existing filterNameSpaces() which only matches element identifiers,
    /// this filters by both namespace name AND element identifier.
    private func filterNameSpacesByDeviceRequest(
        nameSpacesValue: CBOR,
        requestedNamespaces: [String: [String: Bool]]
    ) -> CBOR? {
        guard case let .map(nameSpaces) = nameSpacesValue else { return nil }

        var filteredNameSpaces: OrderedDictionary<CBOR, CBOR> = [:]

        for (key, namespaceValue) in nameSpaces {
            guard case let .utf8String(namespaceName) = key else { continue }

            // Only include namespaces that were requested
            guard let requestedElements = requestedNamespaces[namespaceName] else { continue }

            // If the request has an empty elements map, include all elements for this namespace
            if requestedElements.isEmpty {
                filteredNameSpaces[key] = namespaceValue
                continue
            }

            guard case let .array(orgValues) = namespaceValue else { continue }

            var valuesArray: [CBOR] = []
            for value in orgValues {
                if case let .tagged(tag, taggedValue) = value, tag.rawValue == 24 {
                    if case let .byteString(byteString) = taggedValue {
                        if let decodedInnerCBOR = try? CBOR.decode(byteString),
                           case let .map(decodedMap) = decodedInnerCBOR,
                           let identifier = decodedMap[.utf8String("elementIdentifier")],
                           case let .utf8String(identifierString) = identifier {
                            if requestedElements.keys.contains(identifierString) {
                                valuesArray.append(.tagged(tag, .byteString(byteString)))
                            }
                        }
                    }
                }
            }

            if !valuesArray.isEmpty {
                filteredNameSpaces[key] = .array(valuesArray)
            }
        }

        return filteredNameSpaces.isEmpty ? nil : .map(filteredNameSpaces)
    }
}
