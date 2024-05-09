//
//  File.swift
//  
//
//  Created by Mumthasir mohammed on 12/03/24.
//

import Foundation

extension Encodable {
    var dictionary: [String: Any]? {
        guard let data = try? JSONEncoder().encode(self) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed)).flatMap { $0 as? [String: Any] }
    }
}

extension URL {
    public var queryParameters: [String: String]? {
        guard
            let components = URLComponents(url: self, resolvingAgainstBaseURL: true),
            let queryItems = components.queryItems else { return nil }
        return queryItems.reduce(into: [String: String]()) { (result, item) in
            result[item.name] = item.value
        }
    }
}

extension String {
    func decodeBase64() -> String? {
        do {
            var st = self
                .replacingOccurrences(of: "_", with: "/")
                .replacingOccurrences(of: "-", with: "+")
            let remainder = self.count % 4
            if remainder > 0 {
                st = self.padding(toLength: self.count + 4 - remainder,
                                  withPad: "=",
                                  startingAt: 0)
            }
            let data = try Base64.decode(st)
            return String.init(decoding: data, as: UTF8.self)
        }catch{
            debugPrint(error)
            return nil
        }
    }
}

