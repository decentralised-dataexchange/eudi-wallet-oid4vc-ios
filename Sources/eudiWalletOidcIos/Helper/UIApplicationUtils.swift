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

    /// application/x-www-form-urlencoded body, percent-encoding both key and value —
    /// the equivalent of Retrofit's @FormUrlEncoded/@FieldMap on Android. Bodies carrying raw
    /// JSON (authorization_details, client_metadata) or a custom-scheme redirect_uri parse as
    /// garbage without this. Not a drop-in for getPostString: callers that hand over values
    /// they already percent-encoded must keep using that one, or they double-encode.
    func getFormEncodedString(params: [String: Any]) -> String {
        return params.map { key, value in
            "\(percentEscape(key))=\(percentEscape("\(value)"))"
        }.joined(separator: "&")
    }

    /// RFC 3986 unreserved set; everything else is escaped, space as %20. The shared rule for
    /// both form bodies and query values.
    func percentEscape(_ value: String) -> String {
        let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        return value.addingPercentEncoding(withAllowedCharacters: unreserved) ?? value
    }

    /// Query item with an already-escaped value, for URLComponents.percentEncodedQueryItems.
    /// URLComponents.queryItems leaves "+" and "/" literal, and a server that decodes query
    /// parameters form-style then reads every "+" as a space — silently corrupting a client_id
    /// or request_uri. Android escapes these via Uri.Builder.appendQueryParameter.
    func encodedQueryItem(_ name: String, _ value: String?) -> URLQueryItem {
        URLQueryItem(name: percentEscape(name), value: value.map { percentEscape($0) })
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
