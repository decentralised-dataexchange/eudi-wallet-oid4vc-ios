//
//  Error.swift
//  
//
//  Created by Mumthasir mohammed on 19/03/24.
//

import Foundation

struct Error: Codable {
    var message: String?
    var code: Int?
    
    enum CodingKeys: String, CodingKey {
        case message = "message"
        case code = "code"
    }
}
