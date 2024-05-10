//
//  File.swift
//  
//
//  Created by Mumthasir mohammed on 06/03/24.
//

import Foundation

extension Data {
    init<T>(fromArray values: [T]) {
        let values = values
        let ptrUB = values.withUnsafeBufferPointer { (ptr: UnsafeBufferPointer) in return ptr }
        self.init(buffer: ptrUB)
    }

    func urlSafeBase64EncodedString() -> String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    func base64URLEncodedString() -> String {
        var base64String = self.base64EncodedString()
        base64String = base64String.replacingOccurrences(of: "+", with: "-")
        base64String = base64String.replacingOccurrences(of: "/", with: "_")
        base64String = base64String.replacingOccurrences(of: "=", with: "")
        return base64String
    }
    
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddedLength = base64.count + (4 - base64.count % 4) % 4
        base64 = base64.padding(toLength: paddedLength, withPad: "=", startingAt: 0)
        guard let data = Data(base64Encoded: base64) else {
            return nil
        }
        self = data
    }
}

