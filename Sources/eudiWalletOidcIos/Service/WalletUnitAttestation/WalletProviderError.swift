//
//  WalletProviderError.swift
//  eudiWalletOidcIos
//
//  Why a wallet provider protocol 2 request did not succeed.
//

import Foundation

/// The `error_id` values of the wallet provider. Every one starts with
/// `individual_wallet_unit.`.
public enum WalletProviderErrorId {
    public static let appVersionTooOld = "individual_wallet_unit.app_version_too_old"
    public static let appUnknown = "individual_wallet_unit.app_unknown"
    public static let revoked = "individual_wallet_unit.revoked"
    public static let suspended = "individual_wallet_unit.suspended"
    public static let deviceRefused = "individual_wallet_unit.device_refused"
    public static let registeredOnOtherDevice = "individual_wallet_unit.registered_on_other_device"
    public static let appAttestKeyNotRegistered = "individual_wallet_unit.app_attest_key_not_registered"
    public static let unitNotFound = "individual_wallet_unit.unit_not_found"
    public static let revocationCodeExists = "individual_wallet_unit.revocation_code_exists"
    public static let protocol1Refused = "individual_wallet_unit.protocol_1_refused"

    // Handled inside the SDK; the app does not see them unless a retry fails too.
    static let requestSignatureInvalid = "individual_wallet_unit.request_signature_invalid"
    static let appAttestAssertionRefused = "individual_wallet_unit.app_attest_assertion_refused"
    static let appAttestCounterNotIncreased = "individual_wallet_unit.app_attest_counter_not_increased"
    static let deviceRegisteredBefore = "individual_wallet_unit.device_registered_before"
    static let requestKeyInUse = "individual_wallet_unit.request_key_in_use"

    /// Refusals that a new nonce and a new signature or assertion can fix.
    static let retryWithNewNonce: Set<String> = [
        requestSignatureInvalid, appAttestAssertionRefused, appAttestCounterNotIncreased
    ]
}

/// What went wrong on this side of a wallet provider request. Never thrown to
/// the app: ``asEUDIError`` turns it into the outcome's error.
enum WalletProviderError: Error {
    case invalidURL(String)
    case nonceUnavailable
    case bodyNotSerialisable
    /// A key of the request is not an EC JWK, so the request cannot be bound.
    case keyNotBindable
    case requestKey(Error)
    case appAttest(Error)
    /// The request key or the registered App Attest key is gone.
    case keyLost
    case signingFailed
    case transport(String?)
    /// A 2xx whose body is not what the route gives.
    case unexpectedAnswer(Int)
    /// The wallet provider refused; the error carries `errorId` and `reason`.
    case refused(EUDIError)

    var asEUDIError: EUDIError {
        switch self {
        case .refused(let error):
            return error
        case .keyLost:
            return EUDIError(message: "A key of the wallet unit is no longer on this device",
                             code: ErrorCodes.walletUnitKeyLost)
        case .transport(let detail):
            return EUDIError(message: detail ?? "The wallet provider could not be reached",
                             code: ErrorCodes.walletProviderUnreachable)
        case .unexpectedAnswer(let status):
            return EUDIError(message: "The wallet provider answer could not be read",
                             code: ErrorCodes.walletProviderRequestFailed, httpStatus: status)
        case .invalidURL(let url):
            return EUDIError(message: "Invalid wallet provider URL: \(url)", code: ErrorCodes.walletProviderRequestFailed)
        case .nonceUnavailable:
            return EUDIError(message: "No nonce from the wallet provider", code: ErrorCodes.walletProviderRequestFailed)
        case .bodyNotSerialisable:
            return EUDIError(message: "The request body is not valid JSON", code: ErrorCodes.walletProviderRequestFailed)
        case .keyNotBindable:
            return EUDIError(message: "A key of the request is not an EC JWK", code: ErrorCodes.walletProviderRequestFailed)
        case .requestKey(let error):
            return EUDIError(message: "The request key is not available: \(error)", code: ErrorCodes.walletProviderRequestFailed)
        case .appAttest(let error):
            return EUDIError(message: "App Attest failed: \(error)", code: ErrorCodes.walletProviderRequestFailed)
        case .signingFailed:
            return EUDIError(message: "The request could not be signed", code: ErrorCodes.walletProviderRequestFailed)
        }
    }
}
