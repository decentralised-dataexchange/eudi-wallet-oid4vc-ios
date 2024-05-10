import XCTest
@testable import eudi_wallet_oidc_ios

final class eudi_wallet_oidc_iosTests: XCTestCase {
    func testRecieveAndStoreCredential() async throws {
        // XCTest Documentation
        // https://developer.apple.com/documentation/xctest

        // Defining Test Cases and Test Methods
        // https://developer.apple.com/documentation/xctest/defining_test_cases_and_test_methods
        
        // MARK: Resolve credential offer (EWC RFC 001 - 3.1, 3.2)
        // Credential offer is one time usable, please ensure it is replaced before running this test
        // FIXME: Throw error if credential offer is not resolved
        var inTimeCredentialOffer = "openid-credential-offer://?credential_offer_uri=https://oid4vc.igrant.io/organisation/a6b946b8-06a3-445f-8b75-ec0e7b17a040/service/credential-offer/eb0aa2d6-e9f0-4af9-840b-95b468cd7870"
        var resolvedCredentialOffer = try await IssueService.shared.resolveCredentialOffer(credentialOfferString: inTimeCredentialOffer)
        XCTAssertEqual(resolvedCredentialOffer?.grants?.authCode?.preAuthorizedCode, nil)
        XCTAssertNotEqual(resolvedCredentialOffer?.grants?.authorizationCode?.issuerState, nil)
        
        // MARK: Discovery (EWC RFC 001 - 3.3, 3.4)
        var issuerConfig = try? await DiscoveryService.shared.getIssuerConfig(credentialIssuerWellKnownURI: resolvedCredentialOffer?.credentialIssuer)
        var authConfig = try? await DiscoveryService.shared.getAuthConfig(authorisationServerWellKnownURI: issuerConfig?.authorizationServer ?? issuerConfig?.credentialIssuer)
//        debugPrint(issuerConfig)
//        debugPrint(authConfig)
        
        XCTAssertNotNil(authConfig?.authorizationEndpoint)
    }
    
    
}
