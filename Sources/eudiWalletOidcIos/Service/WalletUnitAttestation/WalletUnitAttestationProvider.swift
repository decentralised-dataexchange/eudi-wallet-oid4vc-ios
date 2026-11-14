//
//  WalletUnitAttestationProvider.swift
//  eudiWalletOidcIos
//
//  What an app asks of the wallet provider, whatever protocol it speaks.
//

import Foundation

/// The wallet provider requests of a wallet unit: wallet instance attestations
/// (WIA), the unit status and the revocation code.
///
/// Two implementations:
/// - ``WalletProviderClient``: protocol 2 (signed requests, App Attest attested
///   once, status and revocation code).
/// - ``Protocol1WalletProviderClient``: protocol 1, through
///   ``WalletUnitAttestationService``. It has no status and no revocation code.
///
/// An app holds one provider and makes it in one place, so switching protocol
/// is a change of that one line. Pass the same provider to
/// ``KeyAttestationService`` so key attestation speaks the same protocol.
@available(iOS 14.0, *)
public protocol WalletUnitAttestationProvider: AnyObject {

    /// The wallet provider address the requests go to.
    var baseUrl: String { get }

    /// True when the unit was registered but one of its keys is gone from the
    /// device (a restored backup, a new phone): the app must start a new unit.
    var isKeyLost: Bool { get async }

    /// One WIA bound to `cnfKey`, whose client assertion names the wallet unit
    /// by `clientId`. The answer of a registration carries the revocation code.
    func requestWalletUnitAttestation(
        cnfKey: SecureKeyProtocol,
        clientId: String,
        profile: String?
    ) async -> WalletProviderOutcome<WalletUnitAttestationResponse>

    /// One WIA for each key of `cnfKeys`, index-aligned with the keys. Every
    /// client assertion names the wallet unit by `clientId`.
    func requestWalletUnitAttestations(
        cnfKeys: [SecureKeyProtocol],
        clientId: String,
        profile: String?
    ) async -> WalletProviderOutcome<BatchWalletAttestationResult>

    /// The unit status. `withEvidence`: send device evidence with the read.
    func status(withEvidence: Bool) async -> WalletUnitStatusOutcome

    /// The revocation code of a registered unit that has none yet.
    func revocationCode() async -> WalletUnitRevocationCodeOutcome

    /// Forgets the keys of the unit: the next WIA request registers a new one.
    func reset() async
}

@available(iOS 14.0, *)
extension WalletProviderClient: WalletUnitAttestationProvider {}
