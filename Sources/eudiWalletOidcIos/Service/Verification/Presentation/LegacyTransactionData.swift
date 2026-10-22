//
//  LegacyTransactionData.swift
//  eudiWalletOidcIos
//

import Foundation
import CryptoKit

/// How the previous API used `transaction_data`, kept in one place for the old entry points.
///
/// Only the first entry is read, and it is hashed into the key binding JWT of each query entry its
/// `credential_ids` names. The SCA claims go in only when the caller says so, the request carries
/// transaction data, and it uses DCQL.
enum LegacyTransactionData {

    /// Per entry id, the hashes for its key binding JWT.
    static func hashes(_ request: PresentationRequest?, entryIds: [String]) -> [String: [String]] {
        guard let first = request?.transactionData?.first,
              let decoded = first.decodeBase64(),
              let credentialIds = UIApplicationUtils.shared.convertToDictionary(text: decoded)?["credential_ids"] as? [String] else {
            return [:]
        }
        let hash = Data(SHA256.hash(data: Data(first.utf8))).urlSafeBase64EncodedString()
        var hashes: [String: [String]] = [:]
        for id in entryIds where credentialIds.contains(id) { hashes[id] = [hash] }
        return hashes
    }

    static func isStrongCustomerAuthentication(_ request: PresentationRequest?, flag: Bool) -> Bool {
        flag && request?.dcqlQuery != nil && !(request?.transactionData?.isEmpty ?? true)
    }
}
