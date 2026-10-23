//
//  AuthorizationResponseParameters.swift
//  eudiWalletOidcIos
//

import Foundation

/// The Authorization Response parameters (OpenID4VP 1.0 section 8.1) before encoding.
///
/// `vp_token` under DCQL is "a JSON-encoded object containing entries where the key is the id value
/// used for a Credential Query in the DCQL query and the value is an array of one or more
/// Presentations". Under a presentation definition it is the draft shape: one presentation as a
/// string, several as an array, with the `presentation_submission` beside it.
struct AuthorizationResponseParameters {

    let parameters: [String: Any]

    /// The parameters as form fields: strings as they are, anything else as JSON.
    var formFields: [String: String] {
        parameters.mapValues { value in
            if let text = value as? String { return text }
            return Self.json(value) ?? ""
        }
    }

    /// Whether there is anything for the verifier in it beyond the state.
    var isEmpty: Bool { parameters["vp_token"] == nil && parameters["id_token"] == nil }

    /// The client metadata `version` some draft verifiers send; `draft_23` wants a bare string per entry.
    private static let draft23 = "draft_23"

    static func build(_ request: PresentationRequest, presentations: [Presentation],
                      submission: PresentationSubmissionModel?, idToken: String?) -> AuthorizationResponseParameters {
        var parameters: [String: Any] = [:]
        if let queries = request.dcqlQuery?.credentials {
            let draft23 = metadataVersion(request) == draft23
            var byEntry: [String: Any] = [:]
            for entry in queries {
                let tokens = presentations.filter { $0.entryIds.contains(entry.id) }.map { $0.token }
                guard !tokens.isEmpty else { continue }
                byEntry[entry.id] = draft23 ? tokens[0] : tokens
            }
            parameters["vp_token"] = byEntry
            parameters["state"] = request.state ?? ""
            return AuthorizationResponseParameters(parameters: parameters)
        }

        let responseType = request.responseType ?? ""
        if responseType.contains("vp_token") {
            let tokens = presentations.map { $0.token }
            parameters["vp_token"] = tokens.count == 1 ? tokens[0] : tokens
            if let submission { parameters["presentation_submission"] = dictionary(submission) }
        }
        if responseType.contains("id_token") {
            parameters["id_token"] = idToken ?? ""
        }
        if let state = request.state {
            parameters["state"] = state
        }
        return AuthorizationResponseParameters(parameters: parameters)
    }

    static func json(_ value: Any) -> String? {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: .withoutEscapingSlashes) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func dictionary(_ submission: PresentationSubmissionModel) -> [String: Any] {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        guard let data = try? encoder.encode(submission),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return object
    }

    private static func metadataVersion(_ request: PresentationRequest) -> String? {
        guard let data = request.clientMetaData?.replacingOccurrences(of: "+", with: " ").data(using: .utf8) else { return nil }
        return (try? JSONDecoder().decode(ClientMetaData.self, from: data))?.version
    }
}
