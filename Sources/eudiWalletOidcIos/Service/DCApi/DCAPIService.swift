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
        switch encryptResponse(requestJSON: requestJSON, origin: origin,
                               credentials: credentials, keyHandler: keyHandler) {
        case .success(let encryptionResult):
            guard let responseString = DCAPIResponseBuilder.buildResponseJSONString(
                encryptionResult: encryptionResult
            ) else {
                return .failure(.cborEncodingFailed)
            }
            return .success(responseString)
        case .failure(let error):
            return .failure(error)
        }
    }

    /// Same flow as `processRequest`, but returns the raw encrypted response CBOR bytes
    /// (`["dcapi", {"enc":..., "cipherText":...}]`) instead of the JSON envelope.
    ///
    /// Use this for the iOS DC API where `ISO18013MobileDocumentResponse(responseData:)`
    /// expects the raw response bytes and the platform handles envelope wrapping.
    public func processRequestRawResponse(
        requestJSON: String,
        origin: String,
        credentials: [String],
        keyHandler: SecureKeyProtocol
    ) async -> Result<Data, DCAPIError> {
        switch encryptResponse(requestJSON: requestJSON, origin: origin,
                               credentials: credentials, keyHandler: keyHandler) {
        case .success(let encryptionResult):
            return .success(DCAPIResponseBuilder.buildEncryptedResponseBytes(
                encryptionResult: encryptionResult
            ))
        case .failure(let error):
            return .failure(error)
        }
    }

    /// Shared core: parse request → match credentials → build DeviceResponse → HPKE encrypt.
    private func encryptResponse(
        requestJSON: String,
        origin: String,
        credentials: [String],
        keyHandler: SecureKeyProtocol
    ) -> Result<HPKEEncryptionResult, DCAPIError> {
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

            return .success(encryptionResult)

        } catch let error as DCAPIError {
            return .failure(error)
        } catch {
            return .failure(.invalidRequestJSON(error.localizedDescription))
        }
    }

    /// Extracts decoded element values from a base64url-encoded mDOC credential.
    ///
    /// - Returns: A dictionary keyed by element identifier (e.g. "family_name",
    ///   "age_over_18") with a human-displayable string value (booleans become
    ///   "Yes"/"No", tagged dates unwrap to their inner string).
    public func extractElementValues(credential: String) -> [String: String] {
        guard let nameSpaces = mdocBuilder.getNameSpaces(credential: credential, query: nil),
              case let CBOR.map(nameSpaceMap) = nameSpaces else {
            return [:]
        }

        var result: [String: String] = [:]
        for (_, namespaceValue) in nameSpaceMap {
            guard case let CBOR.array(elements) = namespaceValue else { continue }
            for element in elements {
                guard case let CBOR.tagged(tag, taggedValue) = element, tag.rawValue == 24,
                      case let CBOR.byteString(byteString) = taggedValue,
                      let decoded = try? CBOR.decode([UInt8](Data(byteString))),
                      case let CBOR.map(decodedMap) = decoded,
                      let identifier = decodedMap[CBOR.utf8String("elementIdentifier")],
                      case let CBOR.utf8String(identifierString) = identifier,
                      let value = decodedMap[CBOR.utf8String("elementValue")] else {
                    continue
                }
                result[identifierString] = Self.displayString(for: value)
            }
        }
        return result
    }

    /// Converts a CBOR element value into a human-displayable string.
    private static func displayString(for value: CBOR) -> String {
        switch value {
        case .utf8String(let s):
            return s
        case .boolean(let b):
            return b ? "Yes" : "No"
        case .unsignedInt(let u):
            return String(u)
        case .negativeInt(let n):
            return String(-1 - Int(n))
        case .tagged(_, let inner):
            return displayString(for: inner)
        case .byteString(let bytes):
            return "\(bytes.count) bytes"
        case .double(let d):
            return String(d)
        default:
            return ""
        }
    }

    // MARK: - Private

    private func parseRequestJSON(_ json: String) throws -> (deviceRequest: String, encryptionInfo: String) {
        guard let data = json.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw DCAPIError.invalidRequestJSON("Failed to parse JSON")
        }

        // Supported request envelopes:
        //  1. iOS DC API (direct):  {"deviceRequest":"...","encryptionInfo":"..."}
        //  2. {"protocol":"org-iso-mdoc","data":{"deviceRequest":"...","encryptionInfo":"..."}}
        //  3. {"requests":[{"protocol":"org-iso-mdoc","data":{...}}]}

        // 1. iOS hands the inner data directly — no protocol/data wrapper.
        if let deviceRequestB64 = parsed["deviceRequest"] as? String,
           let encryptionInfoB64 = parsed["encryptionInfo"] as? String {
            return (deviceRequestB64, encryptionInfoB64)
        }

        // 2/3. Browser DC API envelope with protocol + data.
        let firstRequest: [String: Any]
        if let requests = parsed["requests"] as? [[String: Any]], let first = requests.first {
            firstRequest = first
        } else if parsed["protocol"] != nil {
            firstRequest = parsed
        } else {
            throw DCAPIError.invalidRequestJSON("Missing 'deviceRequest'/'encryptionInfo', 'requests' array, or 'protocol' field")
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
