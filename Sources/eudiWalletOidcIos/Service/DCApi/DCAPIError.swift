import Foundation

public enum DCAPIError: Error, LocalizedError {
    case invalidRequestJSON(String)
    case unsupportedProtocol(String)
    case invalidDeviceRequest(String)
    case invalidEncryptionInfo(String)
    case unsupportedCipherSuite(Int)
    case noMatchingCredential(docType: String)
    case deviceSigningFailed
    case hpkeEncryptionFailed(String)
    case cborEncodingFailed

    public var errorDescription: String? {
        switch self {
        case .invalidRequestJSON(let detail):
            return "Invalid DC API request JSON: \(detail)"
        case .unsupportedProtocol(let proto):
            return "Unsupported protocol: \(proto)"
        case .invalidDeviceRequest(let detail):
            return "Invalid DeviceRequest CBOR: \(detail)"
        case .invalidEncryptionInfo(let detail):
            return "Invalid EncryptionInfo CBOR: \(detail)"
        case .unsupportedCipherSuite(let id):
            return "Unsupported cipher suite: \(id)"
        case .noMatchingCredential(let docType):
            return "No matching credential for docType: \(docType)"
        case .deviceSigningFailed:
            return "Device signing failed"
        case .hpkeEncryptionFailed(let detail):
            return "HPKE encryption failed: \(detail)"
        case .cborEncodingFailed:
            return "CBOR encoding failed"
        }
    }
}
