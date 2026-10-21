//
//  RequestObjectParser.swift
//  eudiWalletOidcIos
//

import Foundation

/// The RFC 9101 request object: a JWT whose payload is the set of authorization request
/// parameters. Shared by every source that receives one, by value or by reference.
///
/// Signature verification is not done here. It belongs to the client identifier step, because the
/// key that must have signed the object depends on the client identifier prefix.
enum RequestObjectParser {

    /// True when `data` is a compact JWT, signed or `alg: none`: three segments, the first a JSON
    /// header naming an `alg`. A URI is never taken for one.
    static func looksLikeJwt(_ data: String?) -> Bool {
        guard let data = data?.trimmingCharacters(in: .whitespacesAndNewlines),
              !data.contains("?"), !data.contains("://") else { return false }
        let segments = data.components(separatedBy: ".")
        guard segments.count == 3, let header = header(of: segments[0]) else { return false }
        return header["alg"] is String
    }

    /// The request parameters carried in `jwt`. The `request` field is set to the JWT itself when
    /// the payload does not carry one, so later steps can reach the original object.
    static func parse(_ jwt: String) throws -> PresentationRequest {
        let jwt = jwt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard looksLikeJwt(jwt),
              let payload = try? jwt.decodeJWT(jwtToken: jwt),
              let data = try? JSONSerialization.data(withJSONObject: payload),
              var request = try? JSONDecoder().decode(PresentationRequest.self, from: data) else {
            throw PresentationRequestError.malformed("Invalid Request")
        }
        request.request = request.request ?? jwt
        return request
    }

    /// True when the request object carries no signature: an empty signature segment, or
    /// `alg: none`.
    static func isUnsigned(_ jwt: String) -> Bool {
        let segments = jwt.trimmingCharacters(in: .whitespacesAndNewlines).components(separatedBy: ".")
        guard segments.count == 3 else { return false }
        if segments[2].isEmpty { return true }
        guard let alg = header(of: segments[0])?["alg"] as? String else { return false }
        return alg.caseInsensitiveCompare("none") == .orderedSame
    }

    /// OpenID4VP 1.0 section 5.9: a `redirect_uri` request MUST NOT be signed, so an unsigned
    /// request object is the normal shape for that prefix and is accepted as it is. For every
    /// other prefix the signature is what identifies the verifier, so an unsigned object is
    /// refused unless the policy says otherwise.
    static func requireSignedUnlessRedirectUri(_ jwt: String, _ request: PresentationRequest,
                                               policy: PresentationRequestPolicy) throws {
        if policy.allowUnsignedRequestObjects { return }
        if isUnsigned(jwt), request.clientIDScheme != ClientIdScheme.redirectURI.rawValue {
            debugPrint("RequestObjectParser: unsigned request object for client id scheme '\(request.clientIDScheme ?? "")' - refusing")
            throw PresentationRequestError.unsignedRequestObject
        }
    }

    /// OpenID4VP 1.0 section 5.10.1 and RFC 9101 section 5: when the authorization request URI
    /// carries a `client_id`, it MUST be identical to the request object's, prefix included. The
    /// check only runs when both are present; the request object is the source of truth for
    /// everything else.
    static func requireMatchingClientId(_ clientIdFromUri: String?, _ request: PresentationRequest) throws {
        guard let fromUri = clientIdFromUri, !fromUri.isEmpty,
              let fromObject = request.clientId, !fromObject.isEmpty else { return }
        if fromUri != fromObject {
            throw PresentationRequestError.clientIdMismatch(fromUri: fromUri, fromRequestObject: fromObject)
        }
    }

    /// The client identifier scheme handler, as the request object path has always run it. Leg 2
    /// of the verification revamp replaces it with the client identifier verifier.
    static func verifyClient(_ request: PresentationRequest) async throws -> PresentationRequest {
        let verified: PresentationRequest?
        do {
            verified = try await ClientIdSchemeRequestHandler().handle(jwtRequest: request.request, presentationRequest: request)
        } catch let error as PresentationRequestError {
            throw error
        } catch {
            debugPrint("RequestObjectParser: client identifier check failed: \(error)")
            throw PresentationRequestError.requestValidationFailed
        }
        guard let verified else { throw PresentationRequestError.unrecognisedClient }
        return verified
    }

    private static func header(of segment: String) -> [String: Any]? {
        guard let json = segment.decodeBase64(), let data = json.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}
