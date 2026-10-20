//
//  ErrorCodeTests.swift
//
//  The OAuth error code of a JSON error body is carried on EUDIError, so a
//  wallet can classify an error by code and still show the description.
//

import XCTest
@testable import eudiWalletOidcIos

final class ErrorCodeTests: XCTestCase {

    private func process(_ body: String, contentType: String = "application/json") -> EUDIError? {
        ErrorHandler.processError(data: body.data(using: .utf8), contentType: contentType)
    }

    func testCodeAndDescriptionOfAnOAuthErrorBody() {
        let error = process(#"{"error":"credential_request_denied","error_description":"Credential request denied: the credential configuration does not allow a refresh."}"#)
        XCTAssertEqual(error?.errorCode, "credential_request_denied")
        XCTAssertEqual(error?.message, "Credential request denied: the credential configuration does not allow a refresh.")
    }

    func testCodeAloneBecomesTheMessageToo() {
        let error = process(#"{"error":"invalid_token"}"#)
        XCTAssertEqual(error?.errorCode, "invalid_token")
        XCTAssertEqual(error?.message, "invalid_token")
    }

    func testCodeNestedUnderDetail() {
        let error = process(#"{"detail":{"error":"invalid_nonce","error_description":"nonce expired"}}"#)
        XCTAssertEqual(error?.errorCode, "invalid_nonce")
        XCTAssertEqual(error?.message, "nonce expired")
    }

    func testNoCodeWithoutAJsonErrorField() {
        XCTAssertNil(process(#"{"detail":"Re-issuance is not allowed"}"#)?.errorCode)
        XCTAssertNil(process("<html>Bad gateway</html>", contentType: "text/html")?.errorCode)
        XCTAssertNil(process("No Internet or DNS issue", contentType: "text/plain")?.errorCode)
        XCTAssertNil(process(#"{"error":""}"#)?.errorCode)
    }
}
