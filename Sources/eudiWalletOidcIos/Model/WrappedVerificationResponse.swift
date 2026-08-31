//
//  File.swift
//
//
//  Created by Milan on 05/07/24.
//

import Foundation

public struct WrappedVerificationResponse {
    /// Where to send the user agent next. Kept for source compatibility; it
    /// resolves to `redirectUri` when the Verifier supplied one and falls back
    /// to `location`.
    public var data: String?
    /// The `redirect_uri` from the Verifier's response BODY. This is the only
    /// redirect OpenID4VP 1.0 8.2 defines: the Verifier answers the direct_post
    /// with it, and the Wallet sends the user agent there.
    public var redirectUri: String?
    /// The `Location` header of a 3xx answer. Not part of OpenID4VP - kept only
    /// for wallet-mediated authorization (BankID SUA answers the presentation
    /// with /login;jsessionid=... and the BROWSER must visit it to continue the
    /// authorization to the code). Always ranks below `redirectUri`.
    public var location: String?
    public var error: EUDIError?

    public init(data: String? = nil, redirectUri: String? = nil, location: String? = nil, error: EUDIError? = nil) {
        self.redirectUri = redirectUri
        self.location = location
        self.data = data ?? redirectUri ?? location
        self.error = error
    }

    enum CodingKeys: String, CodingKey {
        case data = "data"
        case error = "error"
    }
}
