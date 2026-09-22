//
//  NotificationEvent.swift
//

import Foundation

/// What the wallet is telling the issuer happened to a credential (section 11.1).
///
/// Named identically on both platforms. This was `NotificationStatus` on iOS and declared **only
/// two of the three values** — there was no way to report a storage failure at all, which is the
/// case the issuer most needs to hear about. Android had all three.
///
/// Mirrors `NotificationEvent` in the Android SDK.
public enum NotificationEvent: String {

    /// Stored successfully.
    case credentialAccepted = "credential_accepted"

    /// Not stored, by the user's choice — declined or deleted.
    case credentialDeleted = "credential_deleted"

    /// Not stored for a technical reason, not a user decision.
    case credentialFailure = "credential_failure"

    public var value: String { rawValue }
}

/// Renamed to ``NotificationEvent``, so both SDKs name it the same thing, and extended with the
/// `credential_failure` case iOS never had.
@available(*, deprecated, renamed: "NotificationEvent")
public typealias NotificationStatus = NotificationEvent
