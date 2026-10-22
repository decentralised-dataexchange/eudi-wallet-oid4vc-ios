//
//  SelectedCredential.swift
//  eudiWalletOidcIos
//

import Foundation

/// What the user picked for one query entry, with the id of the key that binds the credential to
/// this wallet. `keyId` is nil when the credential has no key of its own; the holder's key is used
/// then.
public struct SelectedCredential {

    /// The `QueryEntry` id this credential answers: the DCQL credential query id or the input
    /// descriptor id.
    public let entryId: String

    /// The credential as it should be presented: an SD-JWT with the chosen disclosures, a JWT VC,
    /// or an mdoc IssuerSigned as base64url.
    public let credential: String

    /// The id the credential's key is stored under, resolved through `SecureEnclaveHandler`.
    public let keyId: String?

    public init(entryId: String, credential: String, keyId: String? = nil) {
        self.entryId = entryId
        self.credential = credential
        self.keyId = keyId
    }
}

/// The authentication factors a strong customer authentication flow reports in the key binding
/// JWT's `amr`, beside the possession factor the key itself proves.
public struct AuthenticationMethods {
    public let inherence: String?
    public let knowledge: String?

    public init(inherence: String? = nil, knowledge: String? = nil) {
        self.inherence = inherence
        self.knowledge = knowledge
    }

    public func amr() -> [[String: String]] {
        var amr: [[String: String]] = [["possession": "key_in_local_native_wscd"]]
        inherence.map { amr.append(["inherence": $0]) }
        knowledge.map { amr.append(["knowledge": $0]) }
        return amr
    }
}

/// The credential format identifiers a presentation can take.
public enum PresentationFormat: String {
    case sdJwt = "dc+sd-jwt"
    case mdoc = "mso_mdoc"
    case w3cVp = "jwt_vp"
}

/// One element of the `vp_token`.
public struct Presentation {

    /// The query entries this element answers: one id, or one per credential inside an aggregated
    /// W3C presentation or a DeviceResponse with several documents, in the order they appear in it.
    public let entryIds: [String]
    public let format: PresentationFormat

    /// SD-JWT+KB, a base64url DeviceResponse, or a signed W3C VP JWT.
    public let token: String

    public var entryId: String { entryIds[0] }
}

/// Everything the format builders share for one response.
public struct PresentationInputs {
    public let request: PresentationRequest

    /// The wallet's DID: the W3C presentation holder.
    public let holderDid: String?

    /// The wallet's key: signs the W3C presentation, and whatever has no key of its own.
    public let holderKey: SecureKeyProtocol?

    /// Per query entry id, the base64url hashes of the `transaction_data` entries that name it, for
    /// the key binding JWT. Computed by the caller.
    public let transactionDataHashes: [String: [String]]

    /// True for a TS12 SCA flow: the key binding JWT then carries `response_mode`, `jti` and `amr`.
    public let strongCustomerAuthentication: Bool
    public let authentication: AuthenticationMethods?

    /// RFC 7638 thumbprint of the verifier's encryption key, for the mdoc session transcript. Nil
    /// when the verifier names none.
    public let encryptionKeyThumbprint: [UInt8]?

    public init(request: PresentationRequest, holderDid: String?, holderKey: SecureKeyProtocol?,
                transactionDataHashes: [String: [String]] = [:], strongCustomerAuthentication: Bool = false,
                authentication: AuthenticationMethods? = nil, encryptionKeyThumbprint: [UInt8]? = nil) {
        self.request = request
        self.holderDid = holderDid
        self.holderKey = holderKey
        self.transactionDataHashes = transactionDataHashes
        self.strongCustomerAuthentication = strongCustomerAuthentication
        self.authentication = authentication
        self.encryptionKeyThumbprint = encryptionKeyThumbprint
    }
}
