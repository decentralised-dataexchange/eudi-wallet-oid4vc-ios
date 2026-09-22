//
//  NotificationOutcome.swift
//

import Foundation

/// What the notification request produced.
///
/// Replaces `Void`. The previous implementation decoded the failure into a local named `error` and
/// then discarded it — the compiler warned on every one — so a caller could not tell an
/// acknowledged notification from one the issuer rejected, nor section 11.2's 204 from a 400.
///
/// Mirrors `NotificationOutcome` in the Android SDK.
public enum NotificationOutcome {

    /// Section 11.2: the issuer accepted it. No body is returned.
    case acknowledged

    /// The issuer refused it, with its own error code where it sent one.
    case failed(error: EUDIError)

    public var error: EUDIError? {
        if case let .failed(error) = self { return error }
        return nil
    }
}
