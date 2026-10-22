//
//  TransactionDataRules.swift
//  eudiWalletOidcIos
//

import Foundation
import CryptoKit

/// OpenID4VP 1.0 section 8.4 and Appendix B.3.3: reading, validating and hashing the request's
/// `transaction_data`.
enum TransactionDataRules {

    static let defaultAlgorithm = "sha-256"

    /// IANA Named Information hash names this SDK can compute, in preference order.
    private static let supported = ["sha-256", "sha-384", "sha-512"]

    /// Section 8.5 `invalid_transaction_data`.
    struct InvalidTransactionData: Error, Equatable {
        let detail: String
    }

    /// Every entry, checked against the request. Section 5.1: "The Wallet MUST return an error if a
    /// request contains even one unrecognized transaction data type or transaction data not
    /// conforming to the respective type definition." Section 8.5 lists the cases.
    ///
    /// - Parameter recognisedTypes: the types the host can show the user; nil accepts any type.
    static func entries(_ request: PresentationRequest, recognisedTypes: Set<String>? = nil) throws -> [TransactionDataEntry] {
        let raw = request.transactionData ?? []
        guard !raw.isEmpty else { return [] }
        let queryIds = queryEntryIds(request)
        let unbound = Set((request.dcqlQuery?.credentials ?? [])
            .filter { $0.requireCryptographicHolderBinding == false }.map { $0.id })

        return try raw.enumerated().map { index, value in
            guard let entry = TransactionDataEntry.parse(value) else {
                throw InvalidTransactionData(detail: "transaction_data[\(index)] is not a base64url JSON object with type and credential_ids")
            }
            if let recognisedTypes, !recognisedTypes.contains(entry.type) {
                throw InvalidTransactionData(detail: "the transaction data type \(entry.type) is not supported")
            }
            if let id = entry.credentialIds.first(where: { !queryIds.contains($0) }) {
                throw InvalidTransactionData(detail: "transaction_data[\(index)] names \(id), which the query does not request")
            }
            // B.3.3: "Wallets MUST reject requests with transaction data types that have the
            // require_cryptographic_holder_binding parameter set to false."
            if let id = entry.credentialIds.first(where: { unbound.contains($0) }) {
                throw InvalidTransactionData(detail: "transaction_data[\(index)] names \(id), which is requested without holder binding")
            }
            if !entry.hashAlgorithms.isEmpty, !entry.hashAlgorithms.contains(where: { supported.contains($0) }) {
                throw InvalidTransactionData(detail: "none of the hash algorithms \(entry.hashAlgorithms) is supported")
            }
            return entry
        }
    }

    /// B.3.3.1: one hash per entry that names `entryId`, in request order, made over the string as
    /// received. The algorithm is the first supported one every such entry allows; an entry that
    /// names none allows only `sha-256`. Nil when no entry names `entryId`.
    static func hashes(_ entries: [TransactionDataEntry], entryId: String) throws -> TransactionDataHashes? {
        let naming = entries.filter { $0.credentialIds.contains(entryId) }
        guard !naming.isEmpty else { return nil }
        guard let algorithm = supported.first(where: { name in
            naming.allSatisfy { $0.hashAlgorithms.isEmpty ? name == defaultAlgorithm : $0.hashAlgorithms.contains(name) }
        }) else {
            throw InvalidTransactionData(detail: "the transaction data for \(entryId) allow no common hash algorithm")
        }
        return TransactionDataHashes(algorithm: algorithm, hashes: naming.map { hash($0.raw, algorithm: algorithm) })
    }

    /// The hashes for every query entry the transaction data names.
    static func hashesByEntry(_ entries: [TransactionDataEntry]) throws -> [String: TransactionDataHashes] {
        var out: [String: TransactionDataHashes] = [:]
        for id in entries.flatMap({ $0.credentialIds }) where out[id] == nil {
            out[id] = try hashes(entries, entryId: id)
        }
        return out
    }

    static func hash(_ raw: String, algorithm: String = defaultAlgorithm) -> String {
        let data = Data(raw.utf8)
        let digest: Data
        switch algorithm {
        case "sha-384": digest = Data(SHA384.hash(data: data))
        case "sha-512": digest = Data(SHA512.hash(data: data))
        default: digest = Data(SHA256.hash(data: data))
        }
        return digest.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func queryEntryIds(_ request: PresentationRequest) -> Set<String> {
        if let queries = request.dcqlQuery?.credentials { return Set(queries.map { $0.id }) }
        let definition = try? VerificationService.processPresentationDefinition(request.presentationDefinition)
        return Set(definition?.inputDescriptors?.compactMap { $0.id } ?? [])
    }
}
