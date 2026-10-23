//
//  PresentationDefinitionUriResolver.swift
//  eudiWalletOidcIos
//

import Foundation

/// LEGACY, draft 20 and earlier: dereferences `presentation_definition_uri`. OpenID4VP 1.0 has no
/// such parameter. Delete this file and its call in the resolver to drop support.
///
/// A fetch that fails is a failure of the whole request: a presentation definition request with
/// no definition cannot be matched against anything, so resolving it would only move the error to
/// a later step where its cause is lost.
struct PresentationDefinitionUriResolver {

    let session: URLSession

    /// The presentation definition as a JSON string, the form `PresentationRequest` carries it in.
    /// - Throws: `PresentationRequestError.presentationDefinitionUnavailable`
    func resolve(_ uri: String) async throws -> String {
        guard let url = URL(string: uri) else {
            throw PresentationRequestError.presentationDefinitionUnavailable("presentation_definition_uri is not a valid URL")
        }
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await NetworkLogger.send(URLRequest(url: url), tag: "presentation-definition-uri", session: session)
        } catch {
            throw PresentationRequestError.presentationDefinitionUnavailable(error.localizedDescription)
        }
        if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
            throw PresentationRequestError.presentationDefinitionUnavailable("HTTP \(http.statusCode)")
        }
        var body = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if RequestObjectParser.looksLikeJwt(body),
           let payload = try? body.decodeJWT(jwtToken: body),
           let json = try? JSONSerialization.data(withJSONObject: payload) {
            body = String(data: json, encoding: .utf8) ?? body
        }
        guard (try? VerificationService.processPresentationDefinition(body)) != nil else {
            throw PresentationRequestError.presentationDefinitionUnavailable("the response was not a presentation definition")
        }
        return body
    }
}
