//
//  Date.Extension.swift
//  
//
//  Created by Mumthasir mohammed on 11/03/24.
//

import Foundation

extension Date {
    
    func timeAgoDisplay() -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: self, relativeTo: Date())
    }
    
    var epochTime: String {
        return "\(Int(Date().timeIntervalSince1970))"
    }
    
    var unixTimestamp: Int64 {
        return Int64(self.timeIntervalSince1970 * 1_000)
    }
    
    var epochTimeISO8601: String {
        let unixTime = self.unixTimestamp
        let date = Date(timeIntervalSince1970: TimeInterval(unixTime))
        let iso8601DateFormatter = ISO8601DateFormatter()
        iso8601DateFormatter.formatOptions = [.withInternetDateTime]
        let string = iso8601DateFormatter.string(from: date)
        return string
    }
}
