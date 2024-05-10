//
//  Dictionary.Extension.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//

import Foundation

public extension Dictionary
{
    /**
     Merge with provided dictionary.
     */
    mutating func merge(with dictionary: Dictionary<Key, Value>)
    {
        dictionary.forEach({ (key, value) in
            self.updateValue(value, forKey: key)
        })
    }
    
    func toString() -> String?
    {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: self, options: .withoutEscapingSlashes) else
        {
            return nil
        }
        
        return String(data: jsonData, encoding: .utf8)
    }
    
    func toStringWithSortedKeys() -> String?
    {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: self, options: [.withoutEscapingSlashes, .sortedKeys]) else
        {
            return nil
        }
        
        return String(data: jsonData, encoding: .utf8)
    }
}
