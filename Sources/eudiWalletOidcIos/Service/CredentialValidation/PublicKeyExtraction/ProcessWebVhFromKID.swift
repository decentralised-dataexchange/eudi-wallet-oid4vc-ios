//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 09/12/25.
//

import Foundation

class ProcessWebVhFromKID {

    static func fetchDIDDocument(did: String, session: URLSession = .shared) async throws -> [String: Any]? {
        guard did.hasPrefix("did:webvh:") else { return nil }

        let withoutPrefix = did.replacingOccurrences(of: "did:webvh:", with: "")

        guard let firstColonRange = withoutPrefix.range(of: ":") else {
            return nil
        }

        let encodedPath = String(withoutPrefix[firstColonRange.upperBound...])

        let formattedPath = encodedPath.isEmpty ? "/.well-known" : encodedPath.replacingOccurrences(of: ":", with: "/")

        let decoded = formattedPath.removingPercentEncoding ?? formattedPath

        let cleanedPath = decoded.components(separatedBy: "#").first ?? decoded

        let finalURL = "https://\(cleanedPath)/did.jsonl"

        guard let url = URL(string: finalURL) else { return nil }
        let (data, response) = try await session.data(from: url)
        //let (data, response) = try await URLSession.shared.data(from: url)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }

        guard let jsonArray = try JSONSerialization.jsonObject(with: data) as? [Any] else { return nil }

        guard let objWithValue = jsonArray.first(where: { obj in
            (obj as? [String: Any])?["value"] != nil
        }) as? [String: Any] else { return nil }

        guard
            let value = objWithValue["value"] as? [String: Any],
            let methods = value["verificationMethod"] as? [[String: Any]]
        else { return nil }

        if let match = methods.first(where: { ($0["id"] as? String) == did }) {
            return match["publicKeyJwk"] as? [String: Any]
        }

        return nil
    }
}
