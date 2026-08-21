//
//  StatusClaims.swift
//  eudiWalletOidcIos
//
//  Resolves the credential `status` object across the legacy top-level
//  location and the ARF TS3 WIA `client_status` location.
//

import Foundation

enum StatusClaims {

    /// The effective `status` object: top-level `status`, else
    /// `client_status.status` (the ARF TS3 WIA location).
    static func of(_ payload: [String: Any]?) -> [String: Any]? {
        if let status = payload?["status"] as? [String: Any] {
            return status
        }
        if let clientStatus = payload?["client_status"] as? [String: Any],
           let status = clientStatus["status"] as? [String: Any] {
            return status
        }
        return nil
    }
}
