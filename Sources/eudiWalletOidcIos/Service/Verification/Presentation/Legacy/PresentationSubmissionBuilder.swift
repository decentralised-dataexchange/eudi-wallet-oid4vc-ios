//
//  PresentationSubmissionBuilder.swift
//  eudiWalletOidcIos
//

import Foundation

/// LEGACY, Presentation Exchange: the `presentation_submission` that tells a draft verifier where
/// in the `vp_token` each input descriptor is answered. Paths come from the presentations' final
/// positions; a single presentation is the token itself, so its path is `$`.
struct PresentationSubmissionBuilder {

    func build(_ presentations: [Presentation], definition: PresentationDefinitionModel?) -> PresentationSubmissionModel {
        let single = presentations.count == 1
        var descriptors: [DescriptorMap] = []
        for (index, presentation) in presentations.enumerated() {
            let path = single ? "$" : "$[\(index)]"
            switch presentation.format {
            case .mdoc:
                presentation.entryIds.forEach {
                    descriptors.append(DescriptorMap(id: $0, path: path, format: "mso_mdoc", pathNested: nil))
                }
            case .sdJwt:
                presentation.entryIds.forEach {
                    descriptors.append(DescriptorMap(id: $0, path: path, format: format(definition, $0) ?? PresentationFormat.sdJwt.rawValue,
                                                     pathNested: nil))
                }
            case .w3cVp:
                for (nested, id) in presentation.entryIds.enumerated() {
                    let nestedPath = single ? "$.vp.verifiableCredential[\(nested)]" : "\(path).vp.verifiableCredential[\(nested)]"
                    // As before: a lone presentation names `jwt_vp` when the descriptor or the
                    // definition names a `jwt_vp` format, several name the descriptor's.
                    let outer = single ? (namesJwtVp(definition, id) ? "jwt_vp" : format(definition, id) ?? "")
                        : (format(definition, id) ?? PresentationFormat.w3cVp.rawValue)
                    descriptors.append(DescriptorMap(id: id, path: path, format: outer,
                                                     pathNested: DescriptorMap(id: id, path: nestedPath, format: "jwt_vc", pathNested: nil)))
                }
            }
        }
        return PresentationSubmissionModel(id: UUID().uuidString, definitionID: definition?.id ?? "", descriptorMap: descriptors)
    }

    private func namesJwtVp(_ definition: PresentationDefinitionModel?, _ id: String) -> Bool {
        let own = definition?.inputDescriptors?.first { $0.id == id }?.format?.keys.map { $0 } ?? []
        let all = own + (definition?.format?.keys.map { $0 } ?? [])
        return all.contains { $0.contains("jwt_vp") }
    }

    /// The descriptor's format, or the definition's, with the SD-JWT names normalised as before.
    private func format(_ definition: PresentationDefinitionModel?, _ id: String) -> String? {
        let own = definition?.inputDescriptors?.first { $0.id == id }?.format?.keys
        guard let key = own?.first ?? definition?.format?.keys.first else { return nil }
        switch key {
        case "vcsd-jwt", "vpsd-jwt": return "vc+sd-jwt"
        case "dcsd-jwt": return "dc+sd-jwt"
        default: return key
        }
    }
}
