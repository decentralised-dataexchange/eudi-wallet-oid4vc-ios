//
//  WalletProviderClient.swift
//  eudiWalletOidcIos
//
//  The wallet provider protocol 2 client.
//

import Foundation

/// Talks protocol 2 with the wallet provider: every request except the nonce is
/// signed with the request key of the wallet unit (RFC 9421) and carries App
/// Attest evidence bound to the request.
///
/// - The first WIA request of a wallet unit is its **registration**: a new
///   request key, an App Attest attestation over the request binding of the cnf
///   keys plus the request key, and the `X-Wallet-Unit-Request-Key` header. The
///   answer gives the revocation code once.
/// - Every later request carries an App Attest **assertion** of the same key.
///
/// The requests of the unit go one at a time: a nonce is single use, and the
/// App Attest assertion counter must go up from one request to the next, so
/// nonce, assertion and send must not interleave. An actor alone does not give
/// that (an actor is re-entrant: a second call runs while the first one waits
/// on the network), so every request also waits in ``serialized(_:)`` for the
/// one before it. Use one client for the whole app.
///
/// Refusals that a new nonce fixes (`request_signature_invalid`, an assertion
/// refused, a counter that did not go up) are sent again once here, and so are
/// `device_registered_before` and `request_key_in_use`. Every other refusal
/// comes back in the outcome with `errorId` and `reason`, for the app to act on.
@available(iOS 14.0, *)
public actor WalletProviderClient {

    /// `.../organisation/{id}/service/wallet-provider`.
    public nonisolated let baseUrl: String

    private let appVersion: String
    private let appBuild: String
    private let session: URLSession
    private let requestKeys: WalletUnitRequestKeys
    private let attester: WalletUnitAttester
    private let clock: () -> Date

    /// A key attested for a registration whose answer never came. If the
    /// wallet provider registered it after all, the next registration is
    /// answered with `device_registered_before`, and this is the key it knows.
    private var unconfirmedKeyId: String?

    /// The last request in line; the next one waits for it.
    private var queue: Task<Void, Never>?

    static let clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    /// The covered components of an iOS request, in the order the wallet
    /// provider requires. A registration adds `x-wallet-unit-request-key`.
    static let components = ["@method", "@target-uri", "content-digest", "x-wallet-unit-nonce",
                             "x-wallet-unit-platform", "x-wallet-app-version", "x-wallet-app-build"]
    static let registrationComponent = "x-wallet-unit-request-key"

    /// - Parameters:
    ///   - baseUrl: the wallet provider address, with or without the final
    ///     `/wallet-provider`.
    ///   - appVersion: `CFBundleShortVersionString`, dotted numbers only. The
    ///     wallet provider compares it with the minimum version of the app record.
    ///   - appBuild: `CFBundleVersion`.
    public init(baseUrl: String, appVersion: String, appBuild: String, urlSession: URLSession = .shared) {
        self.init(baseUrl: baseUrl, appVersion: appVersion, appBuild: appBuild, urlSession: urlSession,
                  requestKeys: SecureEnclaveRequestKeys(), attester: AppAttestWalletUnitAttester(),
                  clock: WalletClock.issuedAt)
    }

    init(baseUrl: String, appVersion: String, appBuild: String, urlSession: URLSession,
         requestKeys: WalletUnitRequestKeys, attester: WalletUnitAttester, clock: @escaping () -> Date) {
        self.baseUrl = Self.walletProviderBase(baseUrl)
        self.appVersion = appVersion
        self.appBuild = appBuild
        self.session = urlSession
        self.requestKeys = requestKeys
        self.attester = attester
        self.clock = clock
    }

    /// `.../service/wallet-provider` from either form the app may hold
    /// (`.../service` or `.../service/wallet-provider`).
    static func walletProviderBase(_ url: String) -> String {
        var base = url.trimmingCharacters(in: .whitespaces)
        while base.hasSuffix("/") { base.removeLast() }
        if base.hasSuffix("/wallet-provider") { base.removeLast("/wallet-provider".count) }
        return base + "/wallet-provider"
    }

    // MARK: - State

    /// True when the wallet provider registered this unit and both its keys are
    /// still on the device.
    public var isRegistered: Bool {
        attester.registeredKeyId != nil && requestKeys.current() != nil
    }

    /// True when the unit was registered but one of its keys is gone (a
    /// restored backup, a new phone): the app must start a new wallet unit.
    public var isKeyLost: Bool {
        attester.registeredKeyId != nil && requestKeys.current() == nil
    }

    /// Forgets the request key and the App Attest key: the next WIA request
    /// registers a new wallet unit. The app also makes a new client id.
    public func reset() async {
        await serialized { await self.performReset() }
    }

    private func performReset() {
        requestKeys.remove()
        attester.reset()
        unconfirmedKeyId = nil
    }

    // MARK: - WIA

    /// `POST {base}/wallet-unit/request`: one WIA bound to `cnfKey`, whose
    /// client assertion names the wallet unit by `clientId`. The first request
    /// of a unit registers it and gives the revocation code.
    public func requestWalletUnitAttestation(
        cnfKey: SecureKeyProtocol,
        clientId: String,
        profile: String? = WalletUnitAttestationService.ts3Profile
    ) async -> WalletProviderOutcome<WalletUnitAttestationResponse> {
        await serialized { await self.performWalletUnitAttestation(cnfKey: cnfKey, clientId: clientId, profile: profile) }
    }

    private func performWalletUnitAttestation(
        cnfKey: SecureKeyProtocol,
        clientId: String,
        profile: String?
    ) async -> WalletProviderOutcome<WalletUnitAttestationResponse> {
        guard let cnfJWK = Self.publicJWK(of: cnfKey) else { return .failed(WalletProviderError.keyNotBindable.asEUDIError) }
        let audience = baseUrl
        let result = await send(path: "/wallet-unit/request", cnfJWKs: [cnfJWK], evidence: .registerOrAssert) {
            let assertion = await WalletUnitAttestationService()
                .createClientAssertion(aud: audience, keyHandler: cnfKey, clientId: clientId)
            guard !assertion.isEmpty else { return nil }
            return Self.wiaBody(assertions: .single(assertion), profile: profile)
        }
        switch result {
        case .failure(let error):
            return .failed(error.asEUDIError)
        case .success(let answer):
            guard let json = answer.json,
                  json["walletUnitAttestation"] is String || json["credentialOffer"] is String else {
                return .failed(WalletProviderError.unexpectedAnswer(answer.status).asEUDIError)
            }
            return .success(WalletUnitAttestationResponse(
                credentialOffer: json["credentialOffer"] as? String,
                walletUnitAttestation: json["walletUnitAttestation"] as? String,
                credentialIssuer: json["credentialIssuer"] as? String,
                revocationCode: json["revocationCode"] as? String
            ))
        }
    }

    /// `POST {base}/wallet-unit/request/batch`: one WIA for each key of
    /// `cnfKeys`, one App Attest evidence for all of them. Every client
    /// assertion names the wallet unit by `clientId`.
    public func requestWalletUnitAttestations(
        cnfKeys: [SecureKeyProtocol],
        clientId: String,
        profile: String? = WalletUnitAttestationService.ts3Profile
    ) async -> WalletProviderOutcome<BatchWalletAttestationResult> {
        await serialized { await self.performWalletUnitAttestations(cnfKeys: cnfKeys, clientId: clientId, profile: profile) }
    }

    private func performWalletUnitAttestations(
        cnfKeys: [SecureKeyProtocol],
        clientId: String,
        profile: String?
    ) async -> WalletProviderOutcome<BatchWalletAttestationResult> {
        let jwks = cnfKeys.compactMap { Self.publicJWK(of: $0) }
        guard !cnfKeys.isEmpty, jwks.count == cnfKeys.count else {
            return .failed(WalletProviderError.keyNotBindable.asEUDIError)
        }
        let audience = baseUrl
        var assertions: [String] = []
        let result = await send(path: "/wallet-unit/request/batch", cnfJWKs: jwks, evidence: .registerOrAssert) {
            let service = WalletUnitAttestationService()
            var made: [String] = []
            for key in cnfKeys {
                let assertion = await service.createClientAssertion(aud: audience, keyHandler: key, clientId: clientId)
                guard !assertion.isEmpty else { return nil }
                made.append(assertion)
            }
            assertions = made
            return Self.wiaBody(assertions: .batch(made), profile: profile)
        }
        switch result {
        case .failure(let error):
            return .failed(error.asEUDIError)
        case .success(let answer):
            guard let json = answer.json else { return .failed(WalletProviderError.unexpectedAnswer(answer.status).asEUDIError) }
            let wias = json["walletUnitAttestations"] as? [String] ?? []
            let service = WalletUnitAttestationService()
            var units: [BatchWalletUnit] = []
            for (index, key) in cnfKeys.enumerated() {
                units.append(BatchWalletUnit(
                    index: index,
                    did: await service.createDIDforWUA(keyHandler: key),
                    keyHandler: key,
                    clientAssertion: index < assertions.count ? assertions[index] : "",
                    walletUnitAttestation: index < wias.count ? wias[index] : nil
                ))
            }
            var batch = BatchWalletAttestationResult(
                clientId: clientId,
                requestHash: nil,
                httpCode: answer.status,
                errorBody: nil,
                credentialOffer: json["credentialOffer"] as? String,
                credentialIssuer: json["credentialIssuer"] as? String,
                units: units
            )
            batch.revocationCode = json["revocationCode"] as? String
            return .success(batch)
        }
    }

    // MARK: - Status and revocation code

    /// `POST {base}/wallet-unit/status`, body `{}`. `withEvidence`: send an App
    /// Attest assertion, which the wallet provider asks for when the last answer
    /// had `deviceCheckDue`, or when there is no answer yet.
    public func status(withEvidence: Bool) async -> WalletUnitStatusOutcome {
        await serialized { await self.performStatus(withEvidence: withEvidence) }
    }

    private func performStatus(withEvidence: Bool) async -> WalletUnitStatusOutcome {
        if attester.registeredKeyId == nil { return .notRegistered }
        if requestKeys.current() == nil { return .failed(WalletProviderError.keyLost.asEUDIError) }
        let result = await send(path: "/wallet-unit/status", cnfJWKs: [],
                                evidence: withEvidence ? .assert : .none) { [:] }
        switch result {
        case .success(let answer):
            guard let status = try? JSONDecoder().decode(WalletUnitStatus.self, from: answer.data) else {
                return .failed(WalletProviderError.unexpectedAnswer(answer.status).asEUDIError)
            }
            return .known(status)
        case .failure(.refused(let error)):
            switch error.errorId {
            case WalletProviderErrorId.unitNotFound:
                // The wallet provider does not know the request key: the next
                // WIA request registers the unit again, with a new App Attest key.
                attester.reset()
                return .notRegistered
            case WalletProviderErrorId.revoked:
                return .known(WalletUnitStatus(status: "revoked", reason: error.reason))
            case WalletProviderErrorId.suspended:
                return .known(WalletUnitStatus(status: "suspended", reason: error.reason))
            case nil where error.httpStatus == 404:
                return .notSupported
            default:
                return .failed(error)
            }
        case .failure(let error):
            return .failed(error.asEUDIError)
        }
    }

    /// `POST {base}/wallet-unit/revocation-code`, body `{}`: for a registered
    /// unit whose status says `revocationCodeIssued: false`. Call it once.
    public func revocationCode() async -> WalletUnitRevocationCodeOutcome {
        await serialized { await self.performRevocationCode() }
    }

    private func performRevocationCode() async -> WalletUnitRevocationCodeOutcome {
        guard attester.registeredKeyId != nil else { return .notSupported }
        if requestKeys.current() == nil { return .failed(WalletProviderError.keyLost.asEUDIError) }
        let result = await send(path: "/wallet-unit/revocation-code", cnfJWKs: [], evidence: .none) { [:] }
        switch result {
        case .success(let answer):
            guard let code = answer.json?["revocationCode"] as? String, !code.isEmpty else {
                return .failed(WalletProviderError.unexpectedAnswer(answer.status).asEUDIError)
            }
            return .issued(code)
        case .failure(.refused(let error)):
            if error.errorId == WalletProviderErrorId.revocationCodeExists { return .alreadyIssued }
            if error.errorId == nil && error.httpStatus == 404 { return .notSupported }
            return .failed(error)
        case .failure(let error):
            return .failed(error.asEUDIError)
        }
    }

    // MARK: - Key attestation

    /// `POST {base}/key-attestation` for a registered unit: signed with the
    /// request key, with an assertion over the request binding of the issuer
    /// `cNonce` and the `attestedKeys`. `headers` are sent as they are and not
    /// signed (the OAuth client attestation of the WIA). No retry: the nonce is
    /// the issuer's and cannot be renewed here.
    func keyAttestation(
        body: [String: Any],
        cNonce: String,
        attestedKeys: [[String: Any]],
        headers: [String: String]
    ) async -> Result<Answer, WalletProviderError> {
        await serialized {
            await self.performKeyAttestation(body: body, cNonce: cNonce, attestedKeys: attestedKeys, headers: headers)
        }
    }

    private func performKeyAttestation(
        body: [String: Any],
        cNonce: String,
        attestedKeys: [[String: Any]],
        headers: [String: String]
    ) async -> Result<Answer, WalletProviderError> {
        guard attester.registeredKeyId != nil else { return .failure(.keyLost) }
        return await send(path: "/key-attestation", cnfJWKs: attestedKeys, evidence: .assert,
                          nonce: cNonce, extraHeaders: headers) { body }
    }

    // MARK: - The request cycle

    /// Runs `operation` after every request queued before it has finished.
    private func serialized<T>(_ operation: @escaping () async -> T) async -> T {
        let previous = queue
        let task = Task<T, Never> {
            await previous?.value
            return await operation()
        }
        queue = Task { _ = await task.value }
        return await task.value
    }

    struct Answer {
        let status: Int
        let data: Data
        var json: [String: Any]? { try? JSONSerialization.jsonObject(with: data) as? [String: Any] }
    }

    enum Evidence {
        /// A WIA request: attestation at the registration, else an assertion.
        case registerOrAssert
        /// An assertion of the registered key.
        case assert
        /// No App Attest evidence (signature only).
        case none
    }

    private enum Assertions {
        case single(String)
        case batch([String])
    }

    private static func wiaBody(assertions: Assertions, profile: String?) -> [String: Any] {
        var body: [String: Any] = ["client_assertion_type": clientAssertionType]
        switch assertions {
        case .single(let assertion): body["client_assertion"] = assertion
        case .batch(let all): body["client_assertions"] = all
        }
        if let profile, !profile.isEmpty { body["profile"] = profile }
        return body
    }

    private static func publicJWK(of key: SecureKeyProtocol) -> [String: Any]? {
        guard let publicKey = key.generateSecureKey()?.publicKey else { return nil }
        return key.getJWK(publicKey: publicKey)
    }

    private struct Prepared {
        let request: URLRequest
        /// The App Attest key attested for this request (a registration).
        let attestedKeyId: String?
        let registering: Bool
    }

    /// Gets a nonce (unless `nonce` is given), prepares, signs and sends the
    /// request, and handles the refusals the SDK can fix itself.
    private func send(
        path: String,
        cnfJWKs: [[String: Any]],
        evidence: Evidence,
        nonce givenNonce: String? = nil,
        extraHeaders: [String: String] = [:],
        body: () async -> [String: Any]?
    ) async -> Result<Answer, WalletProviderError> {
        var retriedWithNewNonce = false
        var handledRegisteredBefore = false
        var replacedRequestKey = false

        while true {
            let nonce: String
            if let givenNonce {
                nonce = givenNonce
            } else {
                guard let fetched = await fetchNonce() else { return .failure(.nonceUnavailable) }
                nonce = fetched
            }

            let prepared: Prepared
            switch await prepare(path: path, nonce: nonce, cnfJWKs: cnfJWKs, evidence: evidence,
                                 extraHeaders: extraHeaders, body: body) {
            case .failure(let error): return .failure(error)
            case .success(let value): prepared = value
            }

            let result: HTTPCall.Result
            do {
                result = try await HTTPCall.send(prepared.request, tag: "wallet-provider\(path)", session: session) { detail, _ in
                    WalletProviderError.transport(detail)
                }
            } catch {
                // The wallet provider may have registered the key before the
                // answer was lost.
                if let keyId = prepared.attestedKeyId { unconfirmedKeyId = keyId }
                return .failure(error as? WalletProviderError ?? .transport(nil))
            }

            if result.isSuccessful {
                if let keyId = prepared.attestedKeyId {
                    attester.markRegistered(keyId: keyId)
                    unconfirmedKeyId = nil
                }
                return .success(Answer(status: result.status, data: result.data))
            }

            var error = ErrorHandler.processError(data: result.data, contentType: result.contentType,
                                                  httpStatus: result.status)
                ?? EUDIError(message: "The wallet provider refused the request", httpStatus: result.status)
            if error.httpStatus == nil { error.httpStatus = result.status }
            let errorId = error.errorId ?? ""

            if givenNonce == nil, !retriedWithNewNonce, WalletProviderErrorId.retryWithNewNonce.contains(errorId) {
                retriedWithNewNonce = true
                continue
            }
            if !handledRegisteredBefore, prepared.registering, errorId == WalletProviderErrorId.deviceRegisteredBefore,
               let keyId = unconfirmedKeyId ?? prepared.attestedKeyId {
                // Another request registered the unit first: send again with an assertion.
                handledRegisteredBefore = true
                attester.markRegistered(keyId: keyId)
                unconfirmedKeyId = nil
                continue
            }
            if !replacedRequestKey, prepared.registering, errorId == WalletProviderErrorId.requestKeyInUse {
                // Another unit has this request key: register with a new one.
                replacedRequestKey = true
                requestKeys.remove()
                continue
            }
            return .failure(.refused(error))
        }
    }

    private func prepare(
        path: String,
        nonce: String,
        cnfJWKs: [[String: Any]],
        evidence: Evidence,
        extraHeaders: [String: String],
        body: () async -> [String: Any]?
    ) async -> Result<Prepared, WalletProviderError> {
        let registering = evidence == .registerOrAssert && attester.registeredKeyId == nil

        let requestKey: RequestSigningKey
        if let current = requestKeys.current() {
            requestKey = current
        } else if registering {
            do { requestKey = try requestKeys.make() } catch { return .failure(.requestKey(error)) }
        } else {
            return .failure(.keyLost)
        }

        let boundKeys = registering ? cnfJWKs + [requestKey.publicJWK] : cnfJWKs
        guard let binding = BatchRequestHash.requestBinding(nonce: nonce, jwks: boundKeys) else {
            return .failure(.keyNotBindable)
        }
        let clientDataHash = BatchRequestHash.clientDataHash(binding: binding)

        var evidenceToken: String?
        var appAttestKeyId: String?
        var attestedKeyId: String?
        if registering {
            do {
                let attested = try await attester.attestation(clientDataHash: clientDataHash)
                evidenceToken = attested.attestation.base64URLEncodedString()
                appAttestKeyId = attested.keyId
                attestedKeyId = attested.keyId
            } catch {
                return .failure(.appAttest(error))
            }
        } else if evidence != .none {
            guard let keyId = attester.registeredKeyId else { return .failure(.keyLost) }
            do {
                evidenceToken = try await attester.assertion(keyId: keyId, clientDataHash: clientDataHash)
                    .base64URLEncodedString()
                appAttestKeyId = keyId
            } catch WalletUnitAttesterError.keyLost {
                return .failure(.keyLost)
            } catch {
                return .failure(.appAttest(error))
            }
        }

        guard let bodyObject = await body(),
              JSONSerialization.isValidJSONObject(bodyObject),
              let bodyData = try? JSONSerialization.data(withJSONObject: bodyObject, options: [.withoutEscapingSlashes])
        else { return .failure(.bodyNotSerialisable) }
        guard let url = URL(string: baseUrl + path) else { return .failure(.invalidURL(baseUrl + path)) }

        var headers: [String: String] = [
            "Content-Type": "application/json",
            "Content-Digest": HTTPMessageSignature.contentDigest(body: bodyData),
            "X-Wallet-Unit-Nonce": nonce,
            "X-Wallet-Unit-Platform": "ios",
            "X-Wallet-App-Version": appVersion,
            "X-Wallet-App-Build": appBuild
        ]
        var components = Self.components
        if registering {
            guard let header = Self.requestKeyHeader(requestKey.publicJWK) else { return .failure(.keyNotBindable) }
            headers["X-Wallet-Unit-Request-Key"] = header
            components.append(Self.registrationComponent)
        }

        let signed: HTTPMessageSignature.Signed
        do {
            guard let value = try HTTPMessageSignature.sign(
                method: "POST", targetURI: url.absoluteString, headers: headers, components: components,
                created: Int(clock().timeIntervalSince1970), key: requestKey
            ) else { return .failure(.signingFailed) }
            signed = value
        } catch {
            return .failure(.signingFailed)
        }
        headers["Signature-Input"] = signed.signatureInput
        headers["Signature"] = signed.signature
        if let evidenceToken { headers["X-Wallet-Unit-Integrity-Token"] = evidenceToken }
        if let appAttestKeyId { headers["X-Wallet-Unit-KeyID"] = appAttestKeyId }
        for (name, value) in extraHeaders where headers[name] == nil { headers[name] = value }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = bodyData
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        return .success(Prepared(request: request, attestedKeyId: attestedKeyId, registering: registering))
    }

    /// `X-Wallet-Unit-Request-Key`: base64url (no padding) of the JSON of the
    /// public JWK of the request key.
    static func requestKeyHeader(_ jwk: [String: Any]) -> String? {
        var publicOnly: [String: Any] = [:]
        for member in ["kty", "crv", "x", "y"] { publicOnly[member] = jwk[member] }
        guard let data = try? JSONSerialization.data(withJSONObject: publicOnly, options: [.sortedKeys]) else { return nil }
        return data.base64URLEncodedString()
    }

    /// `POST {base}/nonce`, unsigned: `c_nonce`, else `nonce`. Nil when there is
    /// none: a request must never go with an empty nonce.
    private func fetchNonce() async -> String? {
        guard let url = URL(string: baseUrl + "/nonce") else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        guard let (data, response) = try? await NetworkLogger.send(request, tag: "wallet-provider/nonce", session: session),
              let status = (response as? HTTPURLResponse)?.statusCode, (200..<300).contains(status),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let nonce = (json["c_nonce"] as? String) ?? (json["nonce"] as? String)
        return nonce?.isEmpty == false ? nonce : nil
    }
}
