import Foundation
import SwiftCBOR

public struct ParsedDocRequest {
    public let docType: String
    public let requestedNamespaces: [String: [String: Bool]]
    public let readerAuth: CBOR?
}

public struct ParsedDeviceRequest {
    public let version: String
    public let docRequests: [ParsedDocRequest]
}

public class DeviceRequestParser {

    public static func parse(base64url: String) throws -> ParsedDeviceRequest {
        guard let data = Data(base64URLEncoded: base64url) else {
            throw DCAPIError.invalidDeviceRequest("Invalid base64url encoding")
        }
        return try parse(cborBytes: [UInt8](data))
    }

    public static func parse(cborBytes: [UInt8]) throws -> ParsedDeviceRequest {
        guard let decoded = try? CBOR.decode(cborBytes),
              case let .map(topMap) = decoded else {
            throw DCAPIError.invalidDeviceRequest("Top-level CBOR is not a map")
        }

        let version: String
        if let versionCbor = topMap[.utf8String("version")],
           case let .utf8String(v) = versionCbor {
            version = v
        } else {
            version = "1.0"
        }

        guard let docRequestsCbor = topMap[.utf8String("docRequests")],
              case let .array(docRequestsArray) = docRequestsCbor else {
            throw DCAPIError.invalidDeviceRequest("Missing or invalid 'docRequests' array")
        }

        var docRequests: [ParsedDocRequest] = []
        for docRequestCbor in docRequestsArray {
            guard case let .map(drMap) = docRequestCbor else { continue }

            guard let itemsRequestCbor = drMap[.utf8String("itemsRequest")],
                  case let .tagged(tag, taggedValue) = itemsRequestCbor,
                  tag.rawValue == 24,
                  case let .byteString(innerBytes) = taggedValue else {
                throw DCAPIError.invalidDeviceRequest("Missing or invalid 'itemsRequest' (expected tag 24)")
            }

            guard let itemsRequest = try? CBOR.decode(innerBytes),
                  case let .map(irMap) = itemsRequest else {
                throw DCAPIError.invalidDeviceRequest("Failed to decode ItemsRequest CBOR")
            }

            guard let docTypeCbor = irMap[.utf8String("docType")],
                  case let .utf8String(docType) = docTypeCbor else {
                throw DCAPIError.invalidDeviceRequest("Missing 'docType' in ItemsRequest")
            }

            var requestedNamespaces: [String: [String: Bool]] = [:]
            if let nsCbor = irMap[.utf8String("nameSpaces")],
               case let .map(nsMap) = nsCbor {
                for (nsKey, nsValue) in nsMap {
                    guard case let .utf8String(namespaceName) = nsKey,
                          case let .map(elemMap) = nsValue else { continue }
                    var elements: [String: Bool] = [:]
                    for (elemKey, elemValue) in elemMap {
                        guard case let .utf8String(elemId) = elemKey else { continue }
                        if case let .boolean(retain) = elemValue {
                            elements[elemId] = retain
                        } else {
                            elements[elemId] = false
                        }
                    }
                    requestedNamespaces[namespaceName] = elements
                }
            }

            let readerAuth = drMap[.utf8String("readerAuth")]

            docRequests.append(ParsedDocRequest(
                docType: docType,
                requestedNamespaces: requestedNamespaces,
                readerAuth: readerAuth
            ))
        }

        return ParsedDeviceRequest(version: version, docRequests: docRequests)
    }
}
