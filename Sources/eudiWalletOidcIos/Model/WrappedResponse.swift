//
//  File.swift
//
//
//  Created by Milan on 05/07/24.
//

import Foundation

public struct WrappedResponse {
    public var data: String?
    public var error: EUDIError?
    
    enum CodingKeys: String, CodingKey {
        case data = "data"
        case error = "error"
    }
}
