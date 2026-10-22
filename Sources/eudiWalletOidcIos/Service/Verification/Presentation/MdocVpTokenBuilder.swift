//
//  MdocVpTokenBuilder.swift
//  eudiWalletOidcIos
//

import Foundation
import SwiftCBOR
import OrderedCollections

/// An mdoc presentation: an ISO 18013-5 DeviceResponse carrying the IssuerSigned the wallet
/// selected and a DeviceSigned structure whose signature binds it to the session transcript
/// (OpenID4VP 1.0 Appendix B.2.6). Base64url encoded, as Appendix B.2.4 requires.
///
/// Under DCQL the namespaces are narrowed to the elements the credential query names; with no
/// `claims` every element goes. Under a presentation definition every element goes, as before.
struct MdocVpTokenBuilder {

    /// When true, a document whose key is missing or cannot sign goes out with an empty
    /// `deviceAuth`, which is what the previous API did.
    var unsigned: Bool = false

    private let cbor = MDocVpTokenBuilder()

    /// One DeviceResponse with one document, the 1.0 shape.
    func present(_ selected: SelectedCredential, _ inputs: PresentationInputs, _ transcript: SessionTranscript) throws -> Presentation {
        Presentation(entryIds: [selected.entryId], format: .mdoc,
                     token: encode([try document(selected, inputs, transcript)]))
    }

    /// One DeviceResponse with every document, the draft shape used with a presentation definition.
    func presentAll(_ selected: [SelectedCredential], _ inputs: PresentationInputs, _ transcript: SessionTranscript) throws -> Presentation {
        Presentation(entryIds: selected.map { $0.entryId }, format: .mdoc,
                     token: encode(try selected.map { try document($0, inputs, transcript) }))
    }

    private func document(_ selected: SelectedCredential, _ inputs: PresentationInputs, _ transcript: SessionTranscript) throws -> Document {
        guard let issuerAuth = cbor.getIssuerAuth(credential: selected.credential),
              let nameSpaces = cbor.getNameSpaces(credential: selected.credential, query: nil) else {
            throw PresentationError.unsupportedFormat(selected.entryId)
        }
        let entry = inputs.request.dcqlQuery?.credentials.first { $0.id == selected.entryId }
        let docType = cbor.getDocTypeFromIssuerAuth(cborData: issuerAuth).flatMap { $0.isEmpty ? nil : $0 }
            ?? entry.flatMap { Self.docType($0) }
            ?? (inputs.request.dcqlQuery == nil ? presentationDefinitionDocType(inputs.request) : nil)
            ?? ""
        let disclosed = entry.flatMap { requestedElements($0) }
            .flatMap { cbor.filterNameSpaces(nameSpacesValue: nameSpaces, requestedParams: $0) } ?? nameSpaces

        let emptyNameSpaces = encodeEmptyDeviceNameSpaces()
        var deviceAuth: OrderedDictionary<CBOR, CBOR> = [:]
        do {
            deviceAuth[.utf8String("deviceSignature")] = try signature(selected, inputs, transcript, docType, emptyNameSpaces)
        } catch {
            if !unsigned { throw error }
        }
        return Document(docType: docType, issuerSigned: IssuerSigned(nameSpaces: disclosed, issuerAuth: issuerAuth),
                        deviceSigned: DeviceSigned(nameSpaces: emptyNameSpaces, deviceAuth: .map(deviceAuth)))
    }

    private func signature(_ selected: SelectedCredential, _ inputs: PresentationInputs, _ transcript: SessionTranscript,
                           _ docType: String, _ deviceNameSpaces: CBOR) throws -> CBOR {
        guard let key = PresentationBuilder.key(for: selected, inputs) else { throw PresentationError.noKey(selected.entryId) }
        _ = key.generateSecureKey()
        guard let privateKey = key.getSecurePrivateKey() else { throw PresentationError.noKey(selected.entryId) }
        let authentication = buildDeviceAuthenticationBytes(sessionTranscript: transcript.array, docType: docType,
                                                            deviceNameSpacesBytes: deviceNameSpaces)
        guard let signature = buildDeviceSignatureCoseSign1(deviceAuthenticationBytes: authentication, privateKey: privateKey) else {
            throw PresentationError.deviceSignatureFailed(selected.entryId)
        }
        return signature
    }

    /// The element identifiers a DCQL credential query asks for: the last component of each
    /// claim path. Nil when it names no claims, or when the query is not for an mdoc.
    private func requestedElements(_ entry: CredentialItems) -> [String]? {
        guard let claims = entry.claims else { return nil }
        if case .jwt = entry.meta { return nil }
        return claims.compactMap { claim in
            guard case .pathClaim(let pathClaim) = claim else { return nil }
            return pathClaim.path.compactMap { $0 }.last ?? ""
        }
    }

    private static func docType(_ entry: CredentialItems) -> String? {
        guard case .msoMdoc(let meta) = entry.meta, !meta.doctypeValue.isEmpty else { return nil }
        return meta.doctypeValue
    }

    private func presentationDefinitionDocType(_ request: PresentationRequest) -> String? {
        (try? VerificationService.processPresentationDefinition(request.presentationDefinition))?.docType
    }

    private func encode(_ documents: [Document]) -> String {
        let response = DeviceResponse(version: "1.0", documents: documents, status: 0)
        return Data(response.toCBOR().encode()).urlSafeBase64EncodedString()
    }
}
