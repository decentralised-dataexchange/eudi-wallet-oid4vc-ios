import Foundation

/// Values of `EUDIError.code` that the SDK decides itself. HTTP status codes (100 to 599)
/// are passed through unchanged when a server answers with an error, so a new SDK code must
/// stay outside that range. Add every new code here, with its meaning, so there is one place
/// to look. Mirrors `ErrorCodes` in the Android SDK.
public enum ErrorCodes {

    /// The presentation request carries a `dcql_query` that breaks OpenID4VP 1.0, or one that
    /// cannot be decoded. The message lists every violation. Produced by `DcqlQueryValidator`.
    public static let invalidDcqlQuery = 1001

    /// A wallet provider protocol 2 request could not be made on this device:
    /// no nonce, a key that cannot be bound, the request key or App Attest
    /// refused. Nothing was sent, or the wallet provider gave no usable answer.
    public static let walletProviderRequestFailed = 1101

    /// The wallet provider could not be reached (no network, a timeout). Show
    /// nothing; try again later.
    public static let walletProviderUnreachable = 1102

    /// A key of the wallet unit is gone from this device: the request key or
    /// the registered App Attest key (a restored backup, a new phone). The app
    /// must start a new wallet unit.
    public static let walletUnitKeyLost = 1103
}
