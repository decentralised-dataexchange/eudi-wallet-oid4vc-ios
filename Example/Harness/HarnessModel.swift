//
//  HarnessModel.swift
//  Harness
//

import Foundation
import CryptoKit
import eudiWalletOidcIos

/// Drives the harness: one method per SDK function, each printing its result plus **which internal
/// path answered** -- the source and spec revision that claimed the offer, which of the two
/// well-known URL layouts the issuer actually serves, whether a non-spec fallback was taken.
///
/// None of that is visible from the configuration a host reads, and it is the difference between
/// "this issuer is non-conformant here" and "something is broken".
///
/// Steps 5 onward get a method each as the revamp reaches them.
@MainActor
final class HarnessModel: ObservableObject {

    @Published var scannedInput = ""
    @Published var output = ""
    @Published var isRunning = false

    private var offer: CredentialOffer?
    private var issuerConfig: IssuerWellKnownConfiguration?
    private var authConfig: AuthorisationServerWellKnownConfiguration?

    /// One throwaway identity per scan, not per step: the token request's proof is bound to the key
    /// the authorization request used, so the steps have to present the same wallet.
    private var wallet: WalletIdentity?
    private var codeVerifier: String?

    /// Which transport the request goes through. Browser is what a scanned offer uses; inApp is the
    /// first-party path the wallet-provider attestation bootstrap takes.
    var authorizationMode: AuthorizationMode = .browser

    private let discovery = DiscoveryService()

    func onScanned(_ data: String) {
        scannedInput = data
        offer = nil
        issuerConfig = nil
        authConfig = nil
        wallet = nil
        codeVerifier = nil
        output = ""
        log("Scanned", data)
    }

    func clear() { output = "" }

    // MARK: - Step 1

    /// `IssueService.resolveCredentialOffer(credentialOffer:)`
    func resolveOffer() async {
        await run("1 · Resolve credential offer") {
            let heading = "1 · Resolve credential offer"
            guard !self.scannedInput.trimmingCharacters(in: .whitespaces).isEmpty else {
                self.log(heading, "Scan or paste a credential offer first")
                return false
            }

            let resolver = CredentialOfferResolver()
            let resolved = await resolver.resolve(self.scannedInput)

            if let error = resolved.error {
                self.log(heading, "FAILED\n  \(error.message ?? "unknown")")
                return false
            }
            self.offer = resolved

            self.log(heading, """
              spec revision      \(Self.describe(version: resolved.version))
              credential_issuer  \(resolved.credentialIssuer ?? "—")
              credentials        \(resolved.credentials?.compactMap { $0.types?.last } ?? [])
              formats            \(resolved.credentials?.compactMap { $0.format } ?? [])
              grants             \(Self.describe(grants: resolved.grants))
              tx_code            \(Self.describe(txCode: resolved.grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode?.txCode))
            """)
            return true
        }
    }

    // MARK: - Step 2

    /// `DiscoveryService.getIssuerConfig(credentialIssuerWellKnownURI:)`
    func discoverIssuer() async {
        await run("2 · Discover issuer metadata") {
            let heading = "2 · Discover issuer metadata"
            guard let issuer = self.offer?.credentialIssuer, !issuer.isEmpty else {
                self.log(heading, "Resolve an offer first")
                return false
            }

            let result = await self.discovery.getIssuerConfigDetailed(credentialIssuerWellKnownURI: issuer)
            let diagnostics = result.diagnostics
            let trace = """
              identifier         \(diagnostics.identifier ?? "—")
              urls tried         \(diagnostics.attemptedURLs.count)
            \(diagnostics.attemptedURLs.map { "      \($0)" }.joined(separator: "\n"))
              answered by        \(diagnostics.resolvedURL ?? "nothing")
              url layout         \(Self.describe(form: diagnostics.form, usedFallback: diagnostics.usedSuffixFallback))
              content type       \(diagnostics.contentType ?? "—")
              metadata shape     \(Self.describe(version: diagnostics.specVersion))
            """

            if let error = result.configuration.error {
                self.log(heading, "FAILED\n  \(error.message ?? "unknown")\n\(trace)")
                return false
            }
            self.issuerConfig = result.configuration

            self.log(heading, """
            \(trace)
              credential_endpoint   \(result.configuration.credentialEndpoint ?? "—")
              nonce_endpoint        \(result.configuration.nonceEndPoint ?? "—")
              deferred_endpoint     \(result.configuration.deferredCredentialEndpoint ?? "—")
              authorization_servers \(result.configuration.authorizationServer ?? [])
            """)
            return true
        }
    }

    // MARK: - Step 3

    /// `selectAuthorizationServer` then `DiscoveryService.getAuthConfig(authorisationServerWellKnownURI:)`
    func discoverAuthServer() async {
        await run("3 · Discover authorization server") {
            let heading = "3 · Discover authorization server"
            guard let issuerConfig = self.issuerConfig else {
                self.log(heading, "Discover the issuer metadata first")
                return false
            }

            let selection: AuthorizationServerSelection
            do {
                selection = try self.discovery.selectAuthorizationServer(
                    issuerConfig: issuerConfig, credentialOffer: self.offer
                )
            } catch {
                self.log(heading, "STOPPED\n  \(error.localizedDescription)")
                return false
            }

            let result = await self.discovery.getAuthConfigDetailed(
                authorisationServerWellKnownURI: selection.identifier
            )
            let diagnostics = result.diagnostics
            let trace = """
              selected           \(selection.identifier)
              chosen because     \(selection.source)
              candidates         \(selection.candidates)
              urls tried         \(diagnostics.attemptedURLs.count)
            \(diagnostics.attemptedURLs.map { "      \($0)" }.joined(separator: "\n"))
              answered by        \(diagnostics.resolvedURL ?? "nothing")
              well-known         \(Self.describe(wellKnown: diagnostics.wellKnown, usedFallback: diagnostics.usedOpenIdConfigurationFallback))
            """

            if let error = result.configuration.error {
                self.log(heading, "FAILED\n  \(error.message ?? "unknown")\n\(trace)")
                return false
            }

            self.authConfig = result.configuration
            self.log(heading, """
            \(trace)
              issuer                 \(result.configuration.issuer ?? "—")
              authorization_endpoint \(result.configuration.authorizationEndpoint ?? "—")
              token_endpoint         \(result.configuration.tokenEndpoint ?? "—")
              grant_types            \(result.configuration.grantTypesSupported ?? [])
            """)
            return true
        }
    }

    // MARK: - Step 4

    /// `IssueService.requestAuthorization(session:wallet:...)`
    func requestAuthorization() async {
        await run("4 · Request authorization") {
            let heading = "4 · Request authorization"
            guard let authConfig = self.authConfig else {
                self.log(heading, "Discover the authorization server first")
                return false
            }

            // A pre-authorized offer has no authorization leg at all: the issuer has already
            // decided to issue and handed over the code. Section 4.1.1 puts `issuer_state` inside
            // the authorization_code grant, so an offer without that grant has none to send -- and a
            // server asked for one anyway answers "issuer state is not found".
            let grants = self.offer?.grants
            if grants?.authorizationCode == nil,
               grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode != nil {
                self.log(heading, """
                  skipped            this offer is pre-authorized
                  grants             pre-authorized_code
                  why                a pre-authorized flow has no authorization leg and no
                                     issuer_state to send -- go straight to the token request
                """)
                return false
            }

            let wallet = await self.walletIdentity()
            let verifier = self.codeVerifier ?? CodeVerifierService.shared.generateCodeVerifier() ?? ""
            self.codeVerifier = verifier

            let response = await IssueService(keyHandler: HarnessKeyHandler()).requestAuthorization(
                session: IssuanceSession(
                    credentialOffer: self.offer,
                    issuerConfig: self.issuerConfig,
                    authConfig: authConfig
                ),
                wallet: wallet,
                codeVerifier: verifier,
                mode: self.authorizationMode
            )

            let request = response.request
            // What actually went out. A server rejecting the request is objecting to one of these,
            // and the outcome alone does not say which.
            let sent = (request?.parameters ?? [:])
                .filter { $0.key != "client_metadata" }
                .sorted { $0.key < $1.key }
                .map { "      \($0.key.padding(toLength: max(22, $0.key.count), withPad: " ", startingAt: 0)) \($0.value.prefix(120))" }
                .joined(separator: "\n")

            let trace = """
              transport          \(request?.transport.rawValue ?? "none")
              endpoint           \(request?.endpoint ?? "—")
              redirect_uri       \(request?.redirectUri ?? "—")
              state sent         \(request?.state ?? "—")
              wallet attestation \(request?.sentWalletAttestation == true ? "sent" : "not sent")
              did                \(wallet.did)
              parameters sent    \(request?.parameters.count ?? 0)
            \(sent)
            """

            switch response.outcome {
            case .authorizationCode:
                self.log(heading, """
                \(trace)
                  outcome            authorization code
                  code               \(response.code ?? "—")
                  state returned     \(response.state ?? "—")
                  state matches      \(response.state == request?.state)
                """)
            case .openInBrowser:
                self.log(heading, """
                \(trace)
                  outcome            open in browser
                  expires_in         \(response.expiresIn.map { "\($0) s" } ?? "—")
                  url                \(response.url ?? "—")
                """)
            case .presentationRequired:
                self.log(heading, """
                \(trace)
                  outcome            presentation required (IAR, or a redirect asking for one)
                  auth_session       \(response.authSession ?? "—")
                  expires_in         \(response.expiresIn.map { "\($0) s" } ?? "—")
                  url                \(response.url ?? "—")
                """)
            case .idTokenRequired:
                self.log(heading, """
                \(trace)
                  outcome            id_token required
                  url                \(response.url ?? "—")
                """)
            case .failed:
                self.log(heading, """
                \(trace)
                  outcome            FAILED
                  error              \(response.error?.errorCode ?? "—")
                  description        \(response.error?.message ?? "no reason given")
                  http status        \(response.error?.httpStatus.map(String.init) ?? "—")
                  raw                \(response.error?.raw?.prefix(200).description ?? "—")
                """)
            }
            return response.outcome != .failed
        }
    }

    /// Runs the steps in sequence, stopping at the first that does not produce a result.
    func runAll() async {
        output = ""
        await resolveOffer()
        guard offer != nil else { return }
        await discoverIssuer()
        guard issuerConfig != nil else { return }
        await discoverAuthServer()
        guard authConfig != nil else { return }
        await requestAuthorization()
    }

    /// A throwaway P-256 identity, created once per scan. The harness is not a wallet and holds
    /// nothing between launches.
    private func walletIdentity() async -> WalletIdentity {
        if let wallet { return wallet }
        let key = P256.Signing.PrivateKey()
        let raw = key.publicKey.rawRepresentation
        func base64url(_ data: Data) -> String {
            data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let jwk: [String: Any] = [
            "kty": "EC",
            "crv": "P-256",
            "x": base64url(raw.prefix(32)),
            "y": base64url(raw.suffix(32)),
        ]
        let did = await DidService.shared.createDID(jwk: jwk) ?? ""
        let identity = WalletIdentity(did: did, jwk: jwk)
        wallet = identity
        return identity
    }

    // MARK: - Plumbing

    @discardableResult
    private func run(_ label: String, _ body: () async -> Bool) async -> Bool {
        isRunning = true
        defer { isRunning = false }
        return await body()
    }

    private func log(_ heading: String, _ body: String) {
        if !output.isEmpty { output += "\n\n" }
        output += heading + "\n" + body
    }

    private static func describe(version: String?) -> String {
        switch version {
        case "v2": return "OpenID4VCI 1.0"
        case "v1": return "pre-1.0 draft"
        default: return "unknown (\(version ?? "none"))"
        }
    }

    private static func describe(version: IssuerMetadataSpecVersion?) -> String {
        switch version {
        case .v1_0: return "OpenID4VCI 1.0"
        case .draft: return "pre-1.0 draft"
        case nil: return "—"
        }
    }

    private static func describe(grants: Grants?) -> String {
        var names: [String] = []
        if grants?.authorizationCode != nil { names.append("authorization_code") }
        if grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode != nil { names.append("pre-authorized_code") }
        return names.isEmpty ? "none declared" : names.joined(separator: ", ")
    }

    private static func describe(txCode: TransactionCode?) -> String {
        guard let txCode else { return "—" }
        let length = txCode.length.map(String.init) ?? "unspecified"
        return "length=\(length) input_mode=\(txCode.inputMode ?? "—")"
    }

    private static func describe(form: WellKnownForm?, usedFallback: Bool) -> String {
        guard let form else { return "—" }
        return usedFallback ? "\(form)  ← non-spec fallback" : "\(form)  (spec form)"
    }

    private static func describe(wellKnown: String?, usedFallback: Bool) -> String {
        guard let wellKnown else { return "—" }
        return usedFallback
            ? "\(wellKnown)  ← OpenID Connect Discovery fallback"
            : "\(wellKnown)  (the location OpenID4VCI names)"
    }
}
