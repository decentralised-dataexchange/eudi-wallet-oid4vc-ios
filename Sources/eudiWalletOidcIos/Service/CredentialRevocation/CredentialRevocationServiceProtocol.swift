//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 09/04/25.
//

import Foundation


protocol CredentialRevocationServiceProtocol {
    
    func getRevokedCredentials(credentialList: [String], keyHandler: SecureKeyProtocol) async -> [String]
    func getStatusDetailsFromStatusList(jwt: String?, keyHandler: SecureKeyProtocol) -> (String?, Int?)
    func fetchStatusModel(statusList: [String?]) async -> [StatusListModel]
    
}

enum StatusListRequest {
    /// A GET for a status list. With `useCache` false the local HTTP cache is skipped, so a
    /// revocation shows at once instead of after the server's `Cache-Control: max-age`.
    static func make(_ url: URL, accept: String? = nil, useCache: Bool) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.cachePolicy = useCache ? .useProtocolCachePolicy : .reloadIgnoringLocalCacheData
        if let accept { request.setValue(accept, forHTTPHeaderField: "Accept") }
        return request
    }
}
