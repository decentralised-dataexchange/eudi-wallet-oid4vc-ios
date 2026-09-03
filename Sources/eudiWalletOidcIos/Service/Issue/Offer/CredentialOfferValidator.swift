//
//  CredentialOfferValidator.swift
//  eudiWalletOidcIos
//

import Foundation

/// Spec conformance for a parsed offer, in one place.
///
/// Validation is deliberately separate from parsing: a parser decides *which revision* a document
/// is, this decides whether the document is *usable*. Rules are OpenID4VCI 1.0 section 4.1.1.
struct CredentialOfferValidator {

    private static let inputModeNumeric = "numeric"
    private static let inputModeText = "text"
    private static let maxDescriptionLength = 300

    /// - Returns: the offer, normalised where the specification defines a default.
    /// - Throws: ``CredentialOfferError/invalid(_:)``
    func validate(_ offer: CredentialOffer, specVersion: CredentialOfferSpecVersion) throws -> CredentialOffer {
        var offer = offer

        // credential_issuer: REQUIRED.
        let issuer = offer.credentialIssuer?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let issuer, !issuer.isEmpty else {
            throw CredentialOfferError.invalid("The credential offer does not name an issuer")
        }
        guard Self.isAbsoluteURL(issuer) else {
            throw CredentialOfferError.invalid("The credential offer names an invalid issuer: \(issuer)")
        }
        offer.credentialIssuer = issuer

        // credential_configuration_ids: REQUIRED, non-empty, unique.
        guard let credentials = offer.credentials, !credentials.isEmpty else {
            throw CredentialOfferError.invalid("The credential offer does not name any credentials")
        }
        let identifiers: [String] = credentials.compactMap { credential in
            let value = specVersion == .v1_0 ? credential.types?.first : credential.types?.last
            guard let value, !value.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
            return value
        }
        guard !identifiers.isEmpty else {
            throw CredentialOfferError.invalid("The credential offer does not name any credentials")
        }
        if specVersion == .v1_0, Set(identifiers).count != identifiers.count {
            // Duplicates would otherwise be requested twice.
            throw CredentialOfferError.invalid("The credential offer names the same credential more than once")
        }

        // A pre-authorized grant MUST carry a code.
        if let grant = offer.grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode {
            let code = grant.preAuthorizedCode?.trimmingCharacters(in: .whitespaces)
            guard let code, !code.isEmpty else {
                throw CredentialOfferError.invalid("The credential offer is missing its pre-authorized code")
            }
            if let txCode = grant.txCode {
                offer.grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode?.txCode =
                    Self.normalise(txCode)
            }
        }

        offer.version = specVersion.legacyVersionCode
        return offer
    }

    /// `input_mode` defaults to `numeric`; an unrecognised value falls back to it rather than
    /// failing the offer. `description` MUST NOT exceed 300 characters, and is issuer-controlled
    /// text rendered directly in the PIN screen, so it is truncated rather than trusted.
    private static func normalise(_ txCode: TransactionCode) -> TransactionCode {
        let inputMode: String
        switch txCode.inputMode?.lowercased() {
        case inputModeText: inputMode = inputModeText
        default: inputMode = inputModeNumeric
        }

        var description = txCode.description ?? ""
        if description.count > maxDescriptionLength {
            description = String(description.prefix(maxDescriptionLength))
        }

        // Length is passed through, never invented: a draft offer declares none, and the host
        // decides what to do with that.
        let length = (txCode.length ?? 0) > 0 ? txCode.length : nil
        return TransactionCode(length: length, inputMode: inputMode, description: description)
    }

    private static func isAbsoluteURL(_ value: String) -> Bool {
        guard let components = URLComponents(string: value) else { return false }
        guard let scheme = components.scheme, !scheme.isEmpty else { return false }
        guard let host = components.host, !host.isEmpty else { return false }
        return true
    }
}
