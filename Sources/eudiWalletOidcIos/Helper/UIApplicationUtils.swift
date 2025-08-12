//
//  File.swift
//
//
//  Created by Mumthasir mohammed on 13/03/24.
//

import Foundation

class UIApplicationUtils {
    static let shared = UIApplicationUtils()
    private init(){}
    
    func convertToDictionary(text: String) -> [String: Any?]? {
        return convertStringToDictionary(text: text)
    }
    
    func convertStringToDictionary(text: String) -> [String:Any]? {
        if let data = text.data(using: .utf8) {
            do {
                let json = try JSONSerialization.jsonObject(with: data, options: .mutableContainers) as? [String:AnyObject]
                return json
            } catch {
                print("Something went wrong")
            }
        }
        return nil
    }
    
    func convertStringToDictionaryAny(text: String) -> [String:Any]? {
        if let data = text.data(using: .utf8) {
            do {
                let json = try JSONSerialization.jsonObject(with: data, options: .mutableContainers) as? [String:Any]
                return json
            } catch {
                print("Something went wrong")
            }
        }
        return nil
    }
    
    // Constructs a URL-encoded string from the given parameters dictionary.
    func getPostString(params: [String:Any]) -> String {
        var data = [String]()
        for(key, value) in params {
            data.append(key + "=\(value)")
        }
        return data.map { String($0) }.joined(separator: "&")
    }
}

extension String {
    func decodeJWT(jwtToken jwt: String) throws -> [String: Any] {
        func base64Decode(_ base64: String) throws -> Data? {
            let base64 = base64
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            let padded = base64.padding(toLength: ((base64.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
            guard let decoded = Data(base64Encoded: padded) else {
                debugPrint("DecodeErrors.badToken")
                return nil
            }
            return decoded
        }

        func decodeJWTPart(_ value: String) throws -> [String: Any] {
            guard let bodyData = try base64Decode(value) else { return [:]}
            let json = try JSONSerialization.jsonObject(with: bodyData, options: [])
            guard let payload = json as? [String: Any] else {
                debugPrint("DecodeErrors.other")
                return [:]
            }
            return payload
        }

        let segments = jwt.components(separatedBy: ".")
        return try decodeJWTPart(segments[1])
    }
}

extension Encodable {
    func toJSONString() -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        
        if let jsonData = try? encoder.encode(self) {
            return String(data: jsonData, encoding: .utf8)
        }
        
        return nil
    }
}
