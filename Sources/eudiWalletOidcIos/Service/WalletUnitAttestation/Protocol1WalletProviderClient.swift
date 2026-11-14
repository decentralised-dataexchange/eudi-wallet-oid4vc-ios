//
//  Protocol1WalletProviderClient.swift
//  eudiWalletOidcIos
//
//  The wallet provider protocol 1 behind the provider interface.
//

import Foundation

/// Protocol 1 through ``WalletUnitAttestationService``, for an app that must go
/// back from ``WalletProviderClient``: every WIA request attests a key with App
/// Attest, nothing is signed, and the wallet provider has no unit status and
/// no revocation code (both answer `notSupported`).
///
/// The requests behave as the old service does. The single route signs the
/// client assertion with `cnfKey` and names the unit by the did:key of that
/// key, so pass the key whose did:key is `clientId`. An HTTP refusal comes back
/// as `.failed` with `httpStatus` and no `errorId`.
@available(iOS 14.0, *)
public final class Protocol1WalletProviderClient: WalletUnitAttestationProvider {

    /// The wallet provider address as the app passes it to the old service.
    public let baseUrl: String

    private let service: () -> Protocol1WalletUnitAttestation

    public convenience init(baseUrl: String) {
        self.init(baseUrl: baseUrl, service: { WalletUnitAttestationService() })
    }

    /// `service` makes a new service per request: the old service keeps the
    /// address of its last request in a member.
    init(baseUrl: String, service: @escaping () -> Protocol1WalletUnitAttestation) {
        self.baseUrl = baseUrl
        self.service = service
    }

    public var isKeyLost: Bool {
        get async { false }
    }

    public func requestWalletUnitAttestation(
        cnfKey: SecureKeyProtocol,
        clientId: String,
        profile: String?
    ) async -> WalletProviderOutcome<WalletUnitAttestationResponse> {
        do {
            let (_, response) = try await service().initiateWalletUnitAttestation(
                walletProviderUrl: baseUrl, profile: profile, keyHandler: cnfKey)
            guard let response, Self.hasValue(response.walletUnitAttestation) || Self.hasValue(response.credentialOffer) else {
                return .failed(EUDIError(message: "The wallet provider gave no attestation",
                                         code: ErrorCodes.walletProviderRequestFailed))
            }
            return .success(response)
        } catch {
            return .failed(EUDIError(message: "Wallet unit attestation failed: \(error)",
                                     code: ErrorCodes.walletProviderRequestFailed))
        }
    }

    public func requestWalletUnitAttestations(
        cnfKeys: [SecureKeyProtocol],
        clientId: String,
        profile: String?
    ) async -> WalletProviderOutcome<BatchWalletAttestationResult> {
        guard let result = await service().initiateBatchWalletUnitAttestation(
            walletProviderUrl: baseUrl, keyHandlers: cnfKeys, profile: profile, clientId: clientId) else {
            return .failed(EUDIError(message: "The batch request could not be made",
                                     code: ErrorCodes.walletProviderRequestFailed))
        }
        let refused = result.httpCode.map { !(200..<300).contains($0) } ?? true
        if refused && !result.units.contains(where: { Self.hasValue($0.walletUnitAttestation) }) {
            return .failed(EUDIError(message: result.errorBody ?? "The wallet provider refused the batch request",
                                     code: ErrorCodes.walletProviderRequestFailed,
                                     httpStatus: result.httpCode))
        }
        return .success(result)
    }

    public func status(withEvidence: Bool) async -> WalletUnitStatusOutcome {
        .notSupported
    }

    public func revocationCode() async -> WalletUnitRevocationCodeOutcome {
        .notSupported
    }

    /// Protocol 1 keeps no unit state of its own.
    public func reset() async {}

    private static func hasValue(_ value: String?) -> Bool {
        !(value ?? "").isEmpty
    }
}

/// The two requests of ``WalletUnitAttestationService`` that
/// ``Protocol1WalletProviderClient`` uses; a seam for tests.
@available(iOS 14.0, *)
protocol Protocol1WalletUnitAttestation {
    func initiateWalletUnitAttestation(
        walletProviderUrl: String,
        profile: String?,
        keyHandler: SecureKeyProtocol?
    ) async throws -> (String, WalletUnitAttestationResponse?)

    func initiateBatchWalletUnitAttestation(
        walletProviderUrl: String,
        keyHandlers: [SecureKeyProtocol],
        profile: String?,
        clientId: String?
    ) async -> BatchWalletAttestationResult?
}

@available(iOS 14.0, *)
extension WalletUnitAttestationService: Protocol1WalletUnitAttestation {}
