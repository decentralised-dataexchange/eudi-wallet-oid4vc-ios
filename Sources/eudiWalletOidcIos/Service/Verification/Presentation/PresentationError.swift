//
//  PresentationError.swift
//  eudiWalletOidcIos
//

import Foundation

/// Why a presentation could not be built. The description is meant for a user.
public enum PresentationError: Error, LocalizedError, Equatable {
    /// No key to prove possession with: neither the credential's nor the holder's.
    case noKey(String)
    /// The key binding JWT of an SD-JWT could not be signed.
    case keyBindingFailed(String)
    /// The mdoc device signature could not be made.
    case deviceSignatureFailed(String)
    /// The W3C presentation could not be signed.
    case presentationSigningFailed(String)
    /// The credential is in no format this SDK can present.
    case unsupportedFormat(String)

    public var errorDescription: String? {
        switch self {
        case .noKey(let entryId): return "No key is available to present the credential for \(entryId)"
        case .keyBindingFailed(let entryId): return "The key binding for \(entryId) could not be signed"
        case .deviceSignatureFailed(let entryId): return "The device signature for \(entryId) could not be made"
        case .presentationSigningFailed(let entryId): return "The presentation for \(entryId) could not be signed"
        case .unsupportedFormat(let entryId): return "The credential for \(entryId) is in a format that cannot be presented"
        }
    }
}
