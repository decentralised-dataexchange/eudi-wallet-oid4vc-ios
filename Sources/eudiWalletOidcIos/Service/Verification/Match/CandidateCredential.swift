//
//  CandidateCredential.swift
//  eudiWalletOidcIos
//

import Foundation
import Security

/// One stored credential decoded once for matching, whatever its format, so the matcher never
/// keeps parallel lists aligned by index.
final class CandidateCredential {

    enum Format { case sdJwt, jwtVc, mdoc }

    let raw: String
    let format: Format
    /// The claims as JSON: the SD-JWT payload with disclosures applied, the `vc` object of a JWT
    /// VC, or the mdoc namespaces.
    let json: [String: Any]
    let docType: String?
    /// Section 6.1 `require_cryptographic_holder_binding`: an SD-JWT with `cnf`, a JWT VC with
    /// `cnf` or a DID subject, or an mdoc with a device key.
    let holderBound: Bool
    /// The issuer's certificate chain when the credential carries one (`x5c` header or `x5chain`).
    let certificates: [SecCertificate]
    /// What the trust list lookup is asked about: the leaf certificate, else the issuer DID or kid.
    let trustIdentifier: String?

    private init(raw: String, format: Format, json: [String: Any], docType: String?, holderBound: Bool,
                 certificates: [String], trustIdentifier: String?) {
        self.raw = raw
        self.format = format
        self.json = json
        self.docType = docType
        self.holderBound = holderBound
        self.certificates = certificates.compactMap { item in
            Data(base64Encoded: item).flatMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        }
        self.trustIdentifier = trustIdentifier
    }

    func accepts(_ formatIdentifier: String?) -> Bool {
        switch format {
        case .sdJwt: return formatIdentifier == "dc+sd-jwt" || formatIdentifier == "vc+sd-jwt"
        case .jwtVc: return formatIdentifier == "jwt_vc_json" || formatIdentifier == "jwt_vc"
        case .mdoc: return formatIdentifier == "mso_mdoc"
        }
    }

    static func decode(_ raw: String?) -> CandidateCredential? {
        guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else { return nil }
        return raw.contains(".") ? decodeJwt(raw) : decodeMdoc(raw)
    }

    private static func decodeJwt(_ raw: String) -> CandidateCredential? {
        let issuerJwt = String(raw.split(separator: "~", omittingEmptySubsequences: false).first ?? "")
        let segments = issuerJwt.components(separatedBy: ".")
        guard segments.count == 3, let payload = object(segments[1]),
              let text = FilterCredentialService().processCredentialsToJsonString(credentialList: [raw]).first,
              let json = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] else { return nil }
        let header = object(segments[0]) ?? [:]
        let isSdJwt = raw.contains("~") || payload["vct"] != nil

        var holderBound = payload["cnf"] != nil
        if !isSdJwt && !holderBound {
            // A W3C VC binds its holder through a DID subject rather than cnf.
            let subject = (payload["sub"] as? String)
                ?? (((payload["vc"] as? [String: Any])?["credentialSubject"] as? [String: Any])?["id"] as? String)
            holderBound = subject?.hasPrefix("did:") == true
        }
        let x5c = header["x5c"] as? [String] ?? []
        let (kid, did) = FilterCredentialService().extractDidOrKidFromCredential(data: issuerJwt)
        return CandidateCredential(raw: raw, format: isSdJwt ? .sdJwt : .jwtVc, json: json, docType: nil,
                                   holderBound: holderBound, certificates: x5c, trustIdentifier: x5c.first ?? did ?? kid)
    }

    private static func decodeMdoc(_ raw: String) -> CandidateCredential? {
        let builder = MDocVpTokenBuilder()
        guard let issuerAuth = builder.getIssuerAuth(credential: raw),
              let text = builder.convertCBORtoJson(credential: raw),
              let json = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] else { return nil }
        let filter = FilterCredentialService()
        let x5c = filter.extractX5cFromIssuerAuth1(issuerAuth: issuerAuth) ?? []
        let (kid, did) = filter.extractKidOrDidFromIssuerAuth(issuerAuth: issuerAuth)
        return CandidateCredential(raw: raw, format: .mdoc, json: json, docType: builder.getDocTypeFromIssuerAuth(cborData: issuerAuth),
                                   holderBound: builder.extractDeviceKeyFromIssuerSigned(credential: raw) != nil,
                                   certificates: x5c, trustIdentifier: x5c.first ?? did ?? kid)
    }

    private static func object(_ segment: String) -> [String: Any]? {
        guard let data = Data(base64URLEncoded: segment) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}
