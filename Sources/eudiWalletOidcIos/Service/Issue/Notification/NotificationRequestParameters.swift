//
//  NotificationRequestParameters.swift
//

import Foundation

/// The notification request body, assembled once (section 11.1).
///
/// Mirrors `NotificationRequestParameters` in the Android SDK.
enum NotificationRequestParameters {

    static func build(
        notificationId: String,
        event: NotificationEvent,
        eventDescription: String? = nil
    ) -> [String: Any] {
        var out: [String: Any] = [
            "notification_id": notificationId,
            "event": event.rawValue,
        ]
        // Omitted rather than sent empty, as every other leg omits its blanks.
        if let eventDescription, !eventDescription.trimmingCharacters(in: .whitespaces).isEmpty {
            out["event_description"] = eventDescription
        }
        return out
    }
}
