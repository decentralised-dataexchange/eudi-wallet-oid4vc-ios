//
//  SdJwtVpTokenBuilder.swift
//  eudiWalletOidcIos
//

import Foundation

/// An SD-JWT presentation: the SD-JWT as selected by the wallet, followed by the key binding JWT
/// (SD-JWT VC, OpenID4VP 1.0 Appendix B.3.6).
struct SdJwtVpTokenBuilder {

    /// - Throws: `PresentationError.noKey`, `PresentationError.keyBindingFailed`
    func present(_ selected: SelectedCredential, _ inputs: PresentationInputs) throws -> Presentation {
        let presented = Self.presented(selected)
        guard let key = PresentationBuilder.key(for: selected, inputs) else { throw PresentationError.noKey(selected.entryId) }
        let sca = inputs.strongCustomerAuthentication
        let keyBinding = try KeyBindingJwt.sign(
            entryId: selected.entryId,
            presented: presented,
            key: key,
            audience: inputs.request.clientId,
            nonce: inputs.request.nonce,
            transactionDataHashes: inputs.transactionDataHashes[selected.entryId],
            scaResponseMode: sca ? (inputs.request.responseMode ?? "") : nil,
            amr: sca ? (inputs.authentication ?? AuthenticationMethods()).amr() : nil)
        return Presentation(entryIds: [selected.entryId], format: .sdJwt, token: presented + keyBinding)
    }

    /// The SD-JWT ending with `~`, which is what the key binding JWT follows.
    static func presented(_ selected: SelectedCredential) -> String {
        selected.credential.hasSuffix("~") ? selected.credential : selected.credential + "~"
    }
}
