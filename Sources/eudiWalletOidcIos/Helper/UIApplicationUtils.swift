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
    
    // Constructs a URL-encoded string from the given parameters dictionary.
    func getPostString(params: [String:Any]) -> String {
        var data = [String]()
        for(key, value) in params {
            data.append(key + "=\(value)")
        }
        return data.map { String($0) }.joined(separator: "&")
    }
}
