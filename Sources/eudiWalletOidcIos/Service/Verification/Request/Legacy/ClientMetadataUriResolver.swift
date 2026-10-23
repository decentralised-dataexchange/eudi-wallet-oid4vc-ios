//
//  ClientMetadataUriResolver.swift
//  eudiWalletOidcIos
//

import Foundation

/// LEGACY, draft 20 and earlier: dereferences `client_metadata_uri`. OpenID4VP 1.0 has no such
/// parameter. Delete this file and its call in the resolver to drop support.
///
/// A failure is not fatal: only an encrypted response needs the metadata, and that step reports
/// its absence itself.
struct ClientMetadataUriResolver {

    let session: URLSession

    /// The client metadata as a JSON string, or nil when it could not be fetched.
    func resolve(_ uri: String) async -> String? {
        guard let url = URL(string: uri) else {
            debugPrint("ClientMetadataUriResolver: client_metadata_uri is not a valid URL")
            return nil
        }
        do {
            let (data, response) = try await NetworkLogger.send(URLRequest(url: url), tag: "client-metadata-uri", session: session)
            if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
                debugPrint("ClientMetadataUriResolver: client_metadata_uri answered HTTP \(http.statusCode)")
                return nil
            }
            return String(data: data, encoding: .utf8)
        } catch {
            debugPrint("ClientMetadataUriResolver: client_metadata_uri could not be fetched: \(error)")
            return nil
        }
    }
}
