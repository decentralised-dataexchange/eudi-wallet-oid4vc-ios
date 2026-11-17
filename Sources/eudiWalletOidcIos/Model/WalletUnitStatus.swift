//
//  WalletUnitStatus.swift
//  eudiWalletOidcIos
//
//  Answers of the wallet provider protocol 2 routes.
//

import Foundation

/// The state of a wallet unit at the wallet provider
/// (`POST {base}/wallet-unit/status`).
public struct WalletUnitStatus: Codable, Equatable {
    /// `active`, `suspended` or `revoked`.
    public let status: String
    /// `user_request`, `device_policy`, `wallet_provider`, `key_compromise`,
    /// `app_removed`, or nil.
    public let reason: String?
    /// RFC 3339, when revoked.
    public let revokedAt: String?
    /// The next status read must carry an App Attest assertion.
    public let deviceCheckDue: Bool
    /// False for a unit that registered before it had a revocation code: ask
    /// `wallet-unit/revocation-code` once.
    public let revocationCodeIssued: Bool

    public init(status: String, reason: String? = nil, revokedAt: String? = nil,
                deviceCheckDue: Bool = false, revocationCodeIssued: Bool = true) {
        self.status = status
        self.reason = reason
        self.revokedAt = revokedAt
        self.deviceCheckDue = deviceCheckDue
        self.revocationCodeIssued = revocationCodeIssued
    }

    public var isActive: Bool { status == "active" }
    public var isSuspended: Bool { status == "suspended" }
    /// A revocation is final: send no more WIA requests for this unit.
    public var isRevoked: Bool { status == "revoked" }

    enum CodingKeys: String, CodingKey {
        case status, reason, revokedAt, deviceCheckDue, revocationCodeIssued
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        reason = try container.decodeIfPresent(String.self, forKey: .reason)
        revokedAt = try container.decodeIfPresent(String.self, forKey: .revokedAt)
        deviceCheckDue = try container.decodeIfPresent(Bool.self, forKey: .deviceCheckDue) ?? false
        // A missing member reads as "issued", so the app does not ask for a code
        // a wallet provider cannot give.
        revocationCodeIssued = try container.decodeIfPresent(Bool.self, forKey: .revocationCodeIssued) ?? true
    }
}

/// The result of a protocol 2 request that gives a value.
public enum WalletProviderOutcome<Value> {
    case success(Value)
    /// `error.errorId` and `error.reason` name a refusal of the wallet provider;
    /// `error.code` is one of ``ErrorCodes`` when the SDK could not make the
    /// request or reach the wallet provider.
    case failed(EUDIError)
}

/// The result of a status read.
public enum WalletUnitStatusOutcome {
    case known(WalletUnitStatus)
    /// The wallet provider does not know this unit (404 `unit_not_found`), or
    /// the unit was never registered: the next WIA request registers it.
    case notRegistered
    /// The wallet provider has no protocol 2 (404 without `error_id`). Show nothing.
    case notSupported
    case failed(EUDIError)
}

/// The result of a revocation code request.
public enum WalletUnitRevocationCodeOutcome {
    /// Show the code once; never store it in plain text and never log it.
    case issued(String)
    /// 409 `revocation_code_exists`: another request already got the code.
    case alreadyIssued
    /// The wallet provider has no protocol 2, or the unit is not registered.
    case notSupported
    case failed(EUDIError)
}
