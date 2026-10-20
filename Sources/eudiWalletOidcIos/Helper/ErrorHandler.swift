//
//  File.swift
//
//
//  Created by oem on 05/07/24.
//

import Foundation

class ErrorHandler {
    
    /// Turns whatever a server sent into an ``EUDIError``.
    ///
    /// The message logic below is unchanged and deliberately so -- issuers send several different
    /// shapes and each branch exists because one of them was met in the field. What is new is that
    /// the OAuth `error` **code** now survives alongside the message instead of being overwritten
    /// by it: a standard
    /// `{"error":"invalid_grant","error_description":"Issuer state is not found"}` used to come
    /// back as the sentence alone, leaving callers to string-match prose to decide what to do.
    ///
    /// Mirrors `ErrorHandler.processError` in the Android SDK.
    static func processError(data: Data?, contentType: String? = nil, httpStatus: Int? = nil) -> EUDIError? {
            // Every exit below goes through `decorated` at the end, so the status and the raw body
            // survive on all of them. They used to return early, which meant `httpStatus` was set
            // only when the body happened to be JSON.
            func decorated(_ error: EUDIError?, code: String? = nil, uri: String? = nil, raw: String? = nil) -> EUDIError? {
                var out = error
                out?.errorCode = code
                out?.errorUri = uri
                out?.httpStatus = httpStatus
                out?.raw = raw
                return out
            }

            // Convert Data to String for initial check
            guard let data = data, let dataString = String(data: data, encoding: .utf8) else {
                return decorated(EUDIError(from: ErrorResponse(message:"Unexpected error. Please try again.", code: -1)))
            }

            // Attempt to parse the data string as a JSON object
            let jsonObject: [String: Any]?
            do {
                jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
            } catch {
                if contentType == "text/html" {
                    return decorated(
                        EUDIError(from: ErrorResponse(message:"Unexpected error. Please try again.", code: -1)),
                        raw: dataString
                    )
                } else {
                    return decorated(
                        EUDIError(from: ErrorResponse(
                            message: dataString.isEmpty ? "The request was refused" : dataString,
                            code: -1
                        )),
                        raw: dataString
                    )
                }
            }

            // Determine the error response based on the content of the error message
            let errorResponse: EUDIError?
            if dataString.contains("Invalid Proof JWT: iss doesn't match the expected client_id") {
                errorResponse = EUDIError(from: ErrorResponse(message:"DID is invalid", code: 1))
            } else if let jsonObject = jsonObject {
                if let errorDescription = jsonObject["error_description"] as? String {
                    errorResponse = EUDIError(from: ErrorResponse(message:errorDescription, code: -1))
                } else if let errors = jsonObject["errors"] as? [[String: Any]],
                          let firstError = errors.first,
                          let message = firstError["message"] as? String {
                    errorResponse = EUDIError(from: ErrorResponse(message:message, code: -1))
                } else if let error = jsonObject["error"] as? String {
                    errorResponse = EUDIError(from: ErrorResponse(message:error, code: -1))
                } else if let error = jsonObject["detail"] as? String {
                    errorResponse = EUDIError(from: ErrorResponse(message:error, code: -1))
                } else if let error = jsonObject["detail"] as? [String: Any] {
                    let errorDetail = error["error_description"] as? String
                    errorResponse = EUDIError(from: ErrorResponse(message:errorDetail, code: -1))
                } else if let errorMessage = jsonObject["message"] as? String {
                    errorResponse = EUDIError(from: ErrorResponse(message:errorMessage , code: -1))
                } else {
                    errorResponse = EUDIError(from: ErrorResponse(message:"Unexpected error. Please try again.", code: -1))
                }
            } else {
                errorResponse = EUDIError(from: ErrorResponse(message:"Unexpected error. Please try again.", code: -1))
            }
            // Read the code and the message as the two separate fields they are. `error` is only
            // a code when it is a string: some issuers nest the real pair under `detail`.
            let oauthCode = (jsonObject?["error"] as? String)
                ?? ((jsonObject?["detail"] as? [String: Any])?["error"] as? String)
            let errorUri = jsonObject?["error_uri"] as? String

            return decorated(
                errorResponse,
                code: oauthCode?.isEmpty == false ? oauthCode : nil,
                uri: errorUri,
                raw: dataString
            )
        }
}
