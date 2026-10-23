//
//  VerifierIdentity.swift
//  eudiWalletOidcIos
//

import Foundation
import Security

/// What the client identifier check established about the verifier.
///
/// Identity and trust are kept apart. `verified` says the request was proven to come from the key
/// the `client_id` names, by the rules of its prefix. `anchored` says that key also chains to a
/// trust anchor the policy supplied. Whether a verified verifier is one the user should share
/// with is the host's decision, typically a trust list lookup on `identifier`.
public struct VerifierIdentity {

    public let identifier: ClientIdentifier

    /// The request is authenticated as coming from the client the `client_id` names.
    public let verified: Bool

    /// The verifying key chains to an anchor in the policy (x509 trust anchors, attestation issuer keys).
    public let anchored: Bool

    /// The `x5c` chain of the request object, leaf first, for the x509 prefixes.
    public let certificateChain: [SecCertificate]

    /// `x509_san_dns` only. Section 5.9.3: unless the wallet trusts the client, "the FQDN of the
    /// redirect_uri value MUST match the Client Identifier". Reported rather than enforced, because
    /// the trust decision that waives it is the host's.
    public let redirectUriBound: Bool?

    /// Why `verified` or `anchored` is false, in words for a log line.
    public let reason: String?

    init(identifier: ClientIdentifier, verified: Bool, anchored: Bool = false, certificateChain: [SecCertificate] = [],
         redirectUriBound: Bool? = nil, reason: String? = nil) {
        self.identifier = identifier
        self.verified = verified
        self.anchored = anchored
        self.certificateChain = certificateChain
        self.redirectUriBound = redirectUriBound
        self.reason = reason
    }
}
