//
//  NotificationRequestTests.swift
//

import XCTest
@testable import eudiWalletOidcIos

/// The notification request, section 11.
///
/// `sendNoticationStatus` returned `Void` and decoded its failures into locals it discarded, so
/// none of this was observable to a caller.
///
/// Mirrors `NotificationRequestResolverTest` in the Android SDK.
final class NotificationRequestTests: XCTestCase {

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    private func session(endpoint: String? = "https://issuer.example.com/notification") -> IssuanceSession {
        let json = """
        {
          "credentialIssuer": "https://issuer.example.com",
          "declaresAuthorizationServers": false
          \(endpoint.map { ", \"notificationEndPoint\": \"\($0)\"" } ?? "")
        }
        """
        let config = try! JSONDecoder().decode(IssuerWellKnownConfiguration.self, from: Data(json.utf8))
        return IssuanceSession(credentialOffer: nil, issuerConfig: config, authConfig: nil)
    }

    private func token() -> TokenResponse {
        var token = TokenResponse()
        token.accessToken = "at-1"
        token.tokenType = "Bearer"
        return token
    }

    @discardableResult
    private func notify(
        event: NotificationEvent = .credentialAccepted,
        notificationId: String = "n-1",
        eventDescription: String? = nil,
        session: IssuanceSession? = nil,
        status: Int = 204,
        responseBody: String = ""
    ) async -> (body: [String: Any], outcome: NotificationOutcome, requests: Int) {
        var seen: [String: Any] = [:]
        var requests = 0
        StubURLProtocol.handler = { request in
            requests += 1
            seen = DeferredRequestTests.body(of: request)
            let response = HTTPURLResponse(
                url: request.url!, statusCode: status, httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, Data(responseBody.utf8))
        }
        let outcome = await NotificationRequestResolver().resolve(
            session: session ?? self.session(),
            token: token(),
            notificationId: notificationId,
            event: event,
            eventDescription: eventDescription,
            urlSession: StubURLProtocol.session()
        )
        return (seen, outcome, requests)
    }

    func testA204IsAcknowledged() async {
        let (_, outcome, _) = await notify()
        guard case .acknowledged = outcome else { return XCTFail("expected acknowledged") }
    }

    func testTheBodyNamesTheNotificationAndTheEvent() async {
        let (body, _, _) = await notify(event: .credentialDeleted, notificationId: "n-9")
        XCTAssertEqual(body["notification_id"] as? String, "n-9")
        XCTAssertEqual(body["event"] as? String, "credential_deleted")
    }

    /// iOS could not send this event at all: `NotificationStatus` declared only two of the three.
    func testAStorageFailureCanBeReported() async {
        let (body, _, _) = await notify(
            event: .credentialFailure, eventDescription: "keychain full"
        )
        XCTAssertEqual(body["event"] as? String, "credential_failure")
        XCTAssertEqual(body["event_description"] as? String, "keychain full")
    }

    func testABlankDescriptionIsOmittedRatherThanSentEmpty() async {
        let (body, _, _) = await notify(eventDescription: "  ")
        XCTAssertNil(body["event_description"])
    }

    func testARefusalCarriesTheIssuersCodeAndTheStatus() async {
        let (_, outcome, _) = await notify(
            status: 400, responseBody: #"{"error":"invalid_notification_id"}"#
        )
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertEqual(error.errorCode, "invalid_notification_id")
        XCTAssertEqual(error.httpStatus, 400)
    }

    func testAnIssuerWithNoNotificationEndpointFailsRatherThanPretendingToSend() async {
        let (_, outcome, requests) = await notify(session: session(endpoint: nil))
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(error.message?.contains("notification endpoint") == true, error.message ?? "")
        XCTAssertEqual(requests, 0)
    }

    func testAMissingNotificationIdDoesNotReachTheNetwork() async {
        let (_, outcome, requests) = await notify(notificationId: "")
        guard case .failed = outcome else { return XCTFail("expected failure") }
        XCTAssertEqual(requests, 0)
    }

    func testEveryEventValueIsTheOneTheWireExpects() {
        XCTAssertEqual(NotificationEvent.credentialAccepted.rawValue, "credential_accepted")
        XCTAssertEqual(NotificationEvent.credentialDeleted.rawValue, "credential_deleted")
        XCTAssertEqual(NotificationEvent.credentialFailure.rawValue, "credential_failure")
        XCTAssertEqual(NotificationEvent(rawValue: "credential_failure"), .credentialFailure)
    }
}
