//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 29/09/25.
//

import Foundation
import JOSESwift

public class ReissueService {
    public init() {}
    
    public func reissueCredential(
        did: String,
        nonce: String,
        credentialOffer: CredentialOffer,
        issuerConfig: IssuerWellKnownConfiguration,
        accessToken: String,
        format: String,
        credentialTypes: [String], tokenResponse: TokenResponse? = nil, authDetails: AuthorizationDetails? = nil, privateKey: ECPrivateKey?, keyHandler: SecureEnclaveHandler, attachKeyAttestation: Bool = false, keyAttestationJwt: String? = nil, clientId: String? = nil, preAuthorizedGrantAnonymousAccessSupported: Bool? = nil) async -> CredentialResponse? {

            // Re-issuance is a credential request with a fresh proof; only where the inputs come
            // from differs -- a stored credential record rather than a live offer. It used to be a
            // second copy of the whole leg: its own five-branch body selection, its own plural-proofs
            // trigger, its own transport and its own response decoding, all of which drifted from
            // the credential leg every time that one was fixed.
            let session = IssuanceSession(
                credentialOffer: credentialOffer,
                issuerConfig: issuerConfig,
                authConfig: {
                    var config = AuthorisationServerWellKnownConfiguration()
                    config.preAuthorizedGrantAnonymousAccessSupported =
                        preAuthorizedGrantAnonymousAccessSupported
                    return config
                }()
            )

            var token = tokenResponse ?? TokenResponse()
            token.accessToken = accessToken
            if let authDetails { token.authorizationDetails = [authDetails] }

            let credential = credentialOffer.credentials?.first { entry in
                guard let types = entry.types else {
                    return entry.doctype.map(credentialTypes.contains) ?? false
                }
                return types.contains { credentialTypes.contains($0) }
            } ?? credentialOffer.credentials?.first

            let outcome = await IssueService(keyHandler: keyHandler).requestCredential(
                session: session,
                wallet: WalletIdentity(did: did),
                token: token,
                subject: CredentialSubject.of(session: session, token: token, credential: credential),
                // Appendix F.1: iss is the original grant's client_id, omitted when that token was
                // obtained anonymously. RFC 6749 section 6 binds a refreshed token to the same client.
                issuer: IssueService.proofIssuer(
                    credentialOffer: credentialOffer,
                    preAuthorizedGrantAnonymousAccessSupported: preAuthorizedGrantAnonymousAccessSupported,
                    clientId: clientId,
                    did: did
                ),
                // ARF TS3 v1.5: the wallet-provider Key Attestation travels in the proof header.
                keyAttestation: KeyAttestationService.forProof(
                    walletProviderKa: keyAttestationJwt, attach: attachKeyAttestation
                ),
                encryption: CredentialEncryption(
                    responseKey: privateKey,
                    request: issuerConfig.credentialRequestEncryption
                ),
                nonce: nonce.isEmpty ? nil : nonce
            )
            return CredentialResponse(from: outcome)
        }
    
}

