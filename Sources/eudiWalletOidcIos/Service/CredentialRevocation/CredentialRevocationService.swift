//
//  File.swift
//
//
//  Created by iGrant on 02/12/24.
//

import Foundation
import Compression
import zlib

public class CredentialRevocationService {
    
    public init() {}
    
    /// The credentials in `credentialList` whose status list marks them revoked.
    /// - Parameter useCache: false (default) fetches every status list from the server; true lets
    ///   the HTTP cache serve it for as long as the server's `Cache-Control` allows.
    public func getRevokedCredentials(credentialList: [String], keyHandler: SecureKeyProtocol, useCache: Bool = false) async ->  [String]{
        var statusList: [String] = []
        var statusList2021: [String] = []
        var revokedCredentials: [String] = []
        for item in credentialList {
            let split = item.split(separator: ".")
            if split.count > 1 {
                let jsonString = "\(split[1])".decodeBase64() ?? ""
                let dict = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString)
                if StatusClaims.of(dict) != nil {
                    statusList.append(item)
                }
                if let vc = dict?["vc"] as? [String: Any], let statusListArray = vc["credentialStatus"] as? [String: Any] {
                    statusList2021.append(item)
                }
            } else {
                guard let issuerAuth = MDocVpTokenBuilder().getIssuerAuth(credential: item) else { return  [] }
                let status = MDOCRevocationHelper().getStatusFromIssuerAuth(cborData: issuerAuth)
                if let status = status as? [String: Any] {
                    statusList.append(item)
                }
            }
        }
        if !statusList.isEmpty {
            let revoked  = await IETFCredentialRevocationService(useCache: useCache).getRevokedCredentials(credentialList: statusList, keyHandler: keyHandler)
            revokedCredentials.append(contentsOf: revoked)
        }
        if !statusList2021.isEmpty {
            let revoked = await VerifiableCredentialRevocationService(useCache: useCache).getRevokedCredentials(credentialList: statusList2021, keyHandler: keyHandler)
            revokedCredentials.append(contentsOf: revoked)
        }
        return revokedCredentials
    }
    
}
