import Foundation

/// Values of `EUDIError.code` that the SDK decides itself. HTTP status codes (100 to 599)
/// are passed through unchanged when a server answers with an error, so a new SDK code must
/// stay outside that range. Add every new code here, with its meaning, so there is one place
/// to look. Mirrors `ErrorCodes` in the Android SDK.
public enum ErrorCodes {

    /// The presentation request carries a `dcql_query` that breaks OpenID4VP 1.0, or one that
    /// cannot be decoded. The message lists every violation. Produced by `DcqlQueryValidator`.
    public static let invalidDcqlQuery = 1001
}
