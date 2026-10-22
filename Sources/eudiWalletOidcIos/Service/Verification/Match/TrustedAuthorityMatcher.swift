//
//  TrustedAuthorityMatcher.swift
//  eudiWalletOidcIos
//

import Foundation
import Security
import ASN1Decoder

/// OpenID4VP 1.0 section 6.1.1: "A Credential is identified as a match to a Trusted Authorities
/// Query if it matches with one of the provided values in one of the provided types."
enum TrustedAuthorityMatcher {

    static func matches(_ candidate: CandidateCredential, _ authorities: [TrustedAuthorities]) async -> Bool {
        for authority in authorities {
            let values = authority.values ?? []
            switch authority.type {
            case "aki":
                // 6.1.1.1: the KeyIdentifier of the AuthorityKeyIdentifier, base64url, of any
                // certificate in the credential's chain.
                if candidate.certificates.contains(where: { authorityKeyIdentifier($0).map(values.contains) == true }) {
                    return true
                }
            case "etsi_tl":
                // 6.1.1.2: an entry of the referenced ETSI trusted list. The existing trust list
                // lookup resolves the issuer and names every list it appears in.
                if await inTrustList(candidate, values) { return true }
            default:
                debugPrint("TrustedAuthorityMatcher: trusted_authorities type '\(authority.type ?? "")' is not supported; the entry matches nothing")
            }
        }
        return false
    }

    /// The KeyIdentifier inside the AuthorityKeyIdentifier extension (RFC 5280 section 4.2.1.1),
    /// base64url without padding.
    static func authorityKeyIdentifier(_ certificate: SecCertificate) -> String? {
        // Extension ::= SEQUENCE { extnID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }, the
        // OCTET STRING wrapping SEQUENCE { [0] keyIdentifier OPTIONAL, ... }.
        guard let blocks = try? ASN1DERDecoder.decode(data: SecCertificateCopyData(certificate) as Data),
              let oid = blocks.lazy.compactMap({ $0.findOid("2.5.29.35") }).first,
              let ext = oid.parent,
              let octets = children(ext).last(where: { $0.identifier?.tagNumber() == .octetString }),
              let sequence = children(octets).first(where: { $0.identifier?.tagNumber() == .sequence }),
              let keyId = children(sequence).first(where: {
                  $0.identifier?.typeClass() == .contextSpecific && $0.identifier?.tagNumber().rawValue == 0
              }),
              let bytes = (keyId.value as? Data) ?? keyId.rawValue else { return nil }
        return bytes.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func inTrustList(_ candidate: CandidateCredential, _ values: [String]) async -> Bool {
        guard let identifier = candidate.trustIdentifier, !values.isEmpty else { return false }
        return await withCheckedContinuation { continuation in
            ServerTrustMechanismService.shared.matchedTrustListURLs(x5c: identifier) { urls in
                continuation.resume(returning: urls.contains(where: values.contains))
            }
        }
    }

    private static func children(_ object: ASN1Object) -> [ASN1Object] {
        (0..<object.subCount()).compactMap { object.sub($0) }
    }
}
