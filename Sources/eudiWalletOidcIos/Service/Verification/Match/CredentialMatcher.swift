//
//  CredentialMatcher.swift
//  eudiWalletOidcIos
//

import Foundation

/// Matches the wallet's credentials against one query language.
protocol CredentialMatcher {

    func supports(_ query: PresentationQuery) -> Bool

    /// - Parameter credentials: the wallet's credentials as stored: SD-JWTs and JWTs in compact
    ///   form, mdocs as base64url IssuerSigned. Nil and blank entries are ignored.
    func match(_ query: PresentationQuery, _ credentials: [String?]) async -> CredentialMatches
}
