//
//  CredentialProofs.swift
//

import Foundation

/// What a credential request offers as proof of possession (section 8.2).
///
/// Two shapes, because the issuer's `proof_types_supported` decides which is legal:
///
/// - **`jwt`** — one or more `openid4vci-proof+jwt`. More than one is a *batch*: section 8.2's
///   `proofs` member is an array, and each entry is signed by its own key, so the issuer returns
///   one credential per proof. Every proof carries the same `nonce`, `aud` and `iss`.
/// - **`attestation`** — there is no JWT proof at all. The wallet-provider Key Attestation *is*
///   the proof, and TS3 §2.2.2 / Appendix F.3 require it to carry the issuer's `c_nonce`.
///
/// An enum rather than a `[String]` plus a flag, because "no jwt proofs, use the attestation" and
/// "zero jwt proofs by mistake" are otherwise the same value.
enum CredentialProofs {

    /// One entry is an ordinary request; several is a batch, one credential expected per entry.
    case jwt([String])

    /// The key attestation stands as the proof. Carries it so the request body can name it.
    case attestation(String)

    var isBatch: Bool {
        if case let .jwt(proofs) = self { return proofs.count > 1 }
        return false
    }

    /// How many credentials this request expects back.
    var expectedCredentials: Int {
        if case let .jwt(proofs) = self { return max(proofs.count, 1) }
        return 1
    }
}
