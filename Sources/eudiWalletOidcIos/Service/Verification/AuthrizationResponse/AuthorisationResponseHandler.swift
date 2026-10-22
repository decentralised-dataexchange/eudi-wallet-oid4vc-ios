//
//  AuthorisationResponseHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// The previous API's way to get the encoded response parameters without sending them. Adapts onto
/// `PresentationSubmitter.prepare`; nil when nothing can be sent: an unsupported response mode, a
/// selection that does not match the query, a proof or an encryption that cannot be made.
class AuthorisationResponseHandler {

    func prepareAuthorisationResponse(credentialsList: [[String]]?,
                                      presentationRequest: PresentationRequest?,
                                      did: String, keyHandler: SecureKeyProtocol, isSca: Bool, keyIds: [[String]],
                                      amrInherenceFactor: String?, amrKnowledgeFactor: String?) async -> [String: Any]? {
        guard let request = presentationRequest,
              let selected = LegacySelection.from(request, groups: credentialsList, keyIds: keyIds) else { return nil }
        let mode = ResponseMode.of(request)
        let authentication = isSca ? AuthenticationMethods(inherence: amrInherenceFactor, knowledge: amrKnowledgeFactor) : nil
        return try? await PresentationSubmitter().prepare(PresentationSubmitter.effective(request, mode), mode: mode,
                                                          selected: selected, did: did, holderKey: keyHandler,
                                                          authentication: authentication)
    }
}
