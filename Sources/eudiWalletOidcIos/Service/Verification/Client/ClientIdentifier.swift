//
//  ClientIdentifier.swift
//  eudiWalletOidcIos
//

import Foundation

/// A `client_id` split into its prefix and the identifier the prefix gives meaning to.
///
/// Section 5.9.1: "Wallets MUST use the presence of a : (colon) character and the content
/// preceding it to determine whether a Client Identifier Prefix is used." Section 5.9.2: without a
/// colon, or with an unrecognised prefix, the client is pre-registered.
public struct ClientIdentifier: Equatable {

    public let prefix: ClientIdPrefix

    /// The part the prefix applies to. For legacy and pre-registered clients, the whole client id.
    public let identifier: String

    /// The `client_id` exactly as received; the audience of the presentation.
    public let original: String

    /// Set when the client id carried a prefix this SDK does not know.
    public let unrecognisedPrefix: String?

    init(prefix: ClientIdPrefix, identifier: String, original: String, unrecognisedPrefix: String? = nil) {
        self.prefix = prefix
        self.identifier = identifier
        self.original = original
        self.unrecognisedPrefix = unrecognisedPrefix
    }

    /// - Parameter legacyScheme: the draft 20 `client_id_scheme` parameter, which named the scheme
    ///   outside the client id. Honoured only when the client id itself carries no 1.0 prefix.
    static func parse(_ clientId: String, legacyScheme: String? = nil) -> ClientIdentifier {
        let colon = clientId.firstIndex(of: ":")
        let head = colon.map { String(clientId[..<$0]) } ?? ""
        let fromHead = ClientIdPrefix.from(head.isEmpty ? nil : head)

        if let fromHead, let colon, !fromHead.keepsPrefixInIdentifier {
            return ClientIdentifier(prefix: fromHead, identifier: String(clientId[clientId.index(after: colon)...]),
                                    original: clientId)
        }
        let scheme = legacyScheme?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let scheme = ClientIdPrefix.from(scheme?.isEmpty == false ? scheme : nil) {
            return ClientIdentifier(prefix: scheme, identifier: clientId, original: clientId)
        }
        if let fromHead {
            // https://... and did:... keep the whole value as the identifier.
            return ClientIdentifier(prefix: fromHead, identifier: clientId, original: clientId)
        }
        return ClientIdentifier(prefix: .preRegistered, identifier: clientId, original: clientId,
                                unrecognisedPrefix: head.isEmpty ? nil : head)
    }
}
