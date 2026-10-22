//
//  TransactionDataEntry.swift
//  eudiWalletOidcIos
//

import Foundation

/// One element of the request's `transaction_data` (OpenID4VP 1.0 section 5.1): a base64url encoded
/// JSON object with a `type`, the `credential_ids` that may authorise it, and the type's own
/// parameters.
public struct TransactionDataEntry {

    /// The string exactly as received; section B.3.3.1 hashes it without decoding.
    public let raw: String
    public let type: String
    public let credentialIds: [String]
    /// The `transaction_data_hashes_alg` values, empty when the entry names none.
    public let hashAlgorithms: [String]
    /// The decoded object, for the host to show the transaction to the user.
    public let json: [String: Any]

    /// Nil when `raw` is not base64url JSON with a `type` and a non-empty `credential_ids`.
    public static func parse(_ raw: String) -> TransactionDataEntry? {
        var base64 = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64),
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let type = json["type"] as? String, !type.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        let ids = (json["credential_ids"] as? [Any])?.compactMap { $0 as? String }
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty } ?? []
        guard !ids.isEmpty else { return nil }
        let algorithms: [String]
        switch json["transaction_data_hashes_alg"] {
        case let values as [Any]: algorithms = values.compactMap { $0 as? String }
        case let value as String: algorithms = [value]
        default: algorithms = []
        }
        return TransactionDataEntry(raw: raw, type: type, credentialIds: ids, hashAlgorithms: algorithms, json: json)
    }
}

/// The hashes the key binding JWT carries for one query entry, and the algorithm they were made with.
public struct TransactionDataHashes: Equatable {
    public let algorithm: String
    public let hashes: [String]

    public init(algorithm: String, hashes: [String]) {
        self.algorithm = algorithm
        self.hashes = hashes
    }
}
