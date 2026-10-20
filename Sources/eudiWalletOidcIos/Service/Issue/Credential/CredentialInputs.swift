//
//  CredentialInputs.swift
//
//  What the credential request is given, beyond what steps 3 and 4 already established.
//

import Foundation
import JOSESwift

/// The two halves of credential encryption, which only make sense together.
///
/// The same argument as ``WalletAttestation``: these were separate parameters a caller could
/// mismatch -- a `privateKey` with no request-encryption metadata silently asks for an encrypted
/// response over a plaintext request, and the reverse encrypts the request while asking for the
/// answer in the clear.
///
/// - Parameter responseKey: the key the issuer should encrypt the response to, and the key the
///   response is then decrypted with. `nil` asks for a plaintext response.
/// - Parameter request: the issuer's own `credential_request_encryption` metadata. Section 10: the
///   client "MAY encrypt the request when `encryption_required` is `false` and MUST do so when
///   `encryption_required` is `true`". Left `nil`, the resolver reads it off the session's issuer
///   configuration, which is where it came from in the first place.
///
/// Mirrors `CredentialEncryption` in the Android SDK.
public struct CredentialEncryption {
    public let responseKey: ECPrivateKey?
    public let request: CredentialRequestEncryption?

    public init(responseKey: ECPrivateKey? = nil, request: CredentialRequestEncryption? = nil) {
        self.responseKey = responseKey
        self.request = request
    }

    /// Section 10: the issuer will not accept a plaintext request.
    public var requestEncryptionRequired: Bool { request?.encryptionRequired == true }

    /// The encryption metadata to use, preferring what the caller supplied over the session's.
    func resolved(against session: IssuanceSession) -> CredentialEncryption {
        guard request == nil else { return self }
        return CredentialEncryption(
            responseKey: responseKey,
            request: session.issuerConfig?.credentialRequestEncryption
        )
    }
}
