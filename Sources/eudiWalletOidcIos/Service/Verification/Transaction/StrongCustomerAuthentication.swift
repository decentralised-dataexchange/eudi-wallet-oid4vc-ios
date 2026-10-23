//
//  StrongCustomerAuthentication.swift
//  eudiWalletOidcIos
//

import Foundation

/// The TS12 strong customer authentication transaction types: payment, login_risk, account_access
/// and emandate, as a `urn:eudi:sca:` URN or as an HTTPS transaction-data-type URL. The EWC
/// `payment_data` type and the QES types are not SCA, and must not carry `response_mode` and `amr`
/// in the key binding JWT.
enum StrongCustomerAuthentication {

    private static let urlTypes = ["payment", "login_risk", "account_access", "emandate"]

    static func isScaType(_ type: String) -> Bool {
        type.contains("urn:eudi:sca:") || urlTypes.contains { type.contains("transaction-data-type/\($0)") }
    }

    static func requested(_ entries: [TransactionDataEntry]) -> Bool {
        entries.contains { isScaType($0.type) }
    }
}
