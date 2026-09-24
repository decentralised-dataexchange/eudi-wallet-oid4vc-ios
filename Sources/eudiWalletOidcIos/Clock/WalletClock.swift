//
//  WalletClock.swift
//  eudiWalletOidcIos
//

import Foundation

/// The time source for the short-lived JWTs the wallet mints whose `iat` a
/// remote server checks against its own clock.
///
/// A server with little or no forward tolerance rejects a token it sees in its
/// own future, so `iat`/`nbf` are stamped `skewBackdate` in the past while `exp`
/// is measured from the real `now()`: the token's usable lifetime is unchanged,
/// it only declares an earlier start. This compensates only for a device
/// running ahead of the server, and spends from any maximum-age budget the
/// server enforces, so keep it well under the shortest token lifetime.
public enum WalletClock {

    /// Backdate applied to `iat`/`nbf`. 60 s absorbs ordinary drift without risking a max-age check.
    public static let defaultSkewBackdate: TimeInterval = 60

    private static let lock = NSLock()
    private static var backdate: TimeInterval = defaultSkewBackdate

    public static var skewBackdate: TimeInterval {
        lock.lock(); defer { lock.unlock() }
        return backdate
    }

    /// Sets the skew allowance. Negative values are clamped to zero: post-dating
    /// a token would put it in every server's future.
    public static func configure(skewBackdate: TimeInterval) {
        lock.lock(); backdate = max(0, skewBackdate); lock.unlock()
    }

    /// Real device time. Use for `exp`, so the allowance never shortens a token's life.
    public static func now() -> Date { Date() }

    /// Device time minus the skew allowance. Use for `iat` and `nbf`.
    public static func issuedAt() -> Date { Date().addingTimeInterval(-skewBackdate) }
}
