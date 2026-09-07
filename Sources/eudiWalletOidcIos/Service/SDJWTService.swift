//
//  SDJWTService.swift
//
//
//  Created by Mumthasir mohammed on 26/04/24.
//
import Foundation
import CryptoKit
import PresentationExchangeSdkiOS

public class SDJWTService {
    
    public static var shared = SDJWTService()
    private init() {}
    
    /**
     * Calculates the SHA-256 hash of the input string and returns it in base64url encoding.
     *
     * @param inputString The input string to be hashed.
     * @return The SHA-256 hash of the input string in base64url encoding, or null if the input is null.
     */
    public func calculateSHA256Hash(inputString: String?) -> String? {
        guard let inputString = inputString,
              let inputData = inputString.data(using: .utf8) else {
            return nil
        }
        
        // Compute the SHA-256 hash
        let sha256Digest = SHA256.hash(data: inputData)
        
        // Encode the hash using base64url encoding
        let base64EncodedHash = Data(sha256Digest).base64EncodedString()
        let base64urlEncodedHash = base64EncodedHash
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
        
        return base64urlEncodedHash
    }
    
    public func createSDJWTR(
        credential: String?,
        query: Any?, format: String?
        , keyHandler: SecureKeyProtocol) -> String? {
        do {
            guard let credential = credential else {
                return nil
            }
            let processedCredentialWithRequiredDisclosures = processDisclosures(credential: credential, query: query, format: format, keyHandler: keyHandler)
            return processedCredentialWithRequiredDisclosures
        } catch {
            print("Error creating SD-JWT-R: \(error)")
            return nil
        }
    }
    
    public func processDisclosuresWithPresentationDefinition(
        credential: String?,
        inputDescriptor: InputDescriptor?, format: String?, keyHandler: SecureKeyProtocol) -> String? {
        guard let credential = credential else { return nil }
        
        // Split the credential into disclosures and the issued JWT
        guard let disclosures = getDisclosuresFromSDJWT(credential),
              var issuedJwt = getIssuerJwtFromSDJWT(credential) else {
            return nil
        }
//            if disclosures.count == 0 {
//                return nil
//            }
        var disclosureList: [String] = []
        // Extract requested parameters from the presentation definition
        var requestedParams: [String] = []
            if let fields = inputDescriptor?.constraints?.fields {
            for field in fields {
                if let paramName = field.path?.first?.split(separator: ".").last {
                    requestedParams.append(String(paramName))
                }
            }
        }
        
        // Filter disclosures based on requested parameters
        for disclosure in disclosures {
            if let decodedDisclosure = disclosure.decodeBase64(),
               let list = try? JSONSerialization.jsonObject(with: Data(decodedDisclosure.utf8), options: []) as? [Any],
               list.count >= 2 {
                if let paramName = list[1] as? String,
                    requestedParams.contains(paramName){
                        disclosureList.append(disclosure)
                    }
                if let secondParam = list[2] as? [String: Any] {
                    let keys = Array(secondParam.keys)
                    for key in keys {
                        if requestedParams.contains(key) {
                            disclosureList.append(disclosure)
                        }
                    }
                }
            }
        }
            if let inputDescriptor = inputDescriptor {
                if inputDescriptor.constraints?.limitDisclosure == nil {
                    return issuedJwt.isEmpty ? nil : credential
                } else {
                    var verificationHandler : eudiWalletOidcIos.VerificationService?
                    verificationHandler = eudiWalletOidcIos.VerificationService(keyhandler: keyHandler)
                    let updatedDescriptor = verificationHandler?.updatePath(in: inputDescriptor)
                    var processedCredentials: [String] = []
                    var tempCredentialList: [String?] = []
                    var credentialList: [String] = []
                    var sdList: [String] = []
                    credentialList.append(credential)
                    
                    var credentialFormat: String = ""
                    if let format = format {
                            credentialFormat = format
                    }
                if credentialFormat == "mso_mdoc" {
                    tempCredentialList = credentialList
                    processedCredentials = FilterCredentialService().processCborCredentialToJsonString(credentialList: tempCredentialList) ?? []
                } else {
                    tempCredentialList = FilterCredentialService().splitCredentialsBySdJWT(allCredentials: credentialList, isSdJwt: inputDescriptor.constraints?.limitDisclosure != nil) ?? []
                    
                    processedCredentials = verificationHandler?.processCredentialsToJsonString(credentialList: tempCredentialList) ?? []
                }
                let jsonEncoder = JSONEncoder()
                jsonEncoder.keyEncodingStrategy = .convertToSnakeCase
                guard let jsonData = try? jsonEncoder.encode(updatedDescriptor),
                      let dictionary = try? JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] else {
                    return nil
                }
                // Convert the dictionary to a string
                guard let inputDescriptorString = String(data: try! JSONSerialization.data(withJSONObject: dictionary, options: .withoutEscapingSlashes), encoding: .utf8) else {
                    return nil
                }
                do {
                    
                    let matchesString = try matchCredentials(inputDescriptorJson: inputDescriptorString, credentials: processedCredentials)
                    for item in matchesString {
                        for data in item.fields {
                            let value = data.path.value
                            if let valueDict = value as? [String: Any], let sdArray = valueDict["_sd"] as? [Any] {
                                for element in sdArray {
                                    if let sdValue = element as? String {
                                        sdList.append(sdValue)
                                    }
                                }
                            }
                        }
                    }
                    for dis in disclosures {
                        let sdData = calculateSHA256Hash(inputString: dis) ?? ""
                        if sdList.contains(sdData) {
                            if !(disclosureList.contains(sdData)) {
                                disclosureList.append(dis)
                            }
                        }
                    }
                    let uniqueDisclosureSet = Array(Set(disclosureList))
                    for data in uniqueDisclosureSet {
                        issuedJwt += "~\(data)"
                    }
                    return issuedJwt.isEmpty ? nil : issuedJwt
                } catch {
                    print("error")
                }
            }
        }
        return issuedJwt.isEmpty ? nil : issuedJwt
    }
    
    /// One decoded disclosure: `[salt, name, value]` for an object member,
    /// `[salt, value]` for an array element.
    private struct ParsedDisclosure {
        let encoded: String
        let name: String?
        let value: Any
    }

    /// Selects the disclosures needed to satisfy a set of requested claim paths.
    ///
    /// Matching on the last path component alone is not enough. A claim like
    /// `address.street_address` lives behind two disclosures - one for `address`,
    /// whose value is an `_sd` list, and one for `street_address` inside it. Sending
    /// only the leaf leaves the Verifier with a digest it cannot reach, so the claim
    /// arrives missing even though its disclosure was in the presentation. Walking
    /// the path from the issuer JWT payload downwards collects every disclosure on
    /// the chain, and - because each step only looks at the `_sd` list of the node it
    /// is standing on - it also stops same-named claims under a sibling parent from
    /// being disclosed by accident.
    private func selectDisclosures(payload: [String: Any],
                                   disclosures: [String],
                                   paths: [[String]]) -> [String] {
        var byDigest: [String: ParsedDisclosure] = [:]
        for encoded in disclosures {
            guard let decoded = encoded.decodeBase64(),
                  let list = try? JSONSerialization.jsonObject(with: Data(decoded.utf8),
                                                              options: [.fragmentsAllowed]) as? [Any] else { continue }
            guard let digest = calculateSHA256Hash(inputString: encoded) else { continue }
            if list.count >= 3 {
                byDigest[digest] = ParsedDisclosure(encoded: encoded, name: list[1] as? String, value: list[2])
            } else if list.count == 2 {
                byDigest[digest] = ParsedDisclosure(encoded: encoded, name: nil, value: list[1])
            }
        }

        var selected: Set<String> = []

        /// Everything reachable below `node` - used once a path has been consumed,
        /// which is how a request for a whole object or array (`nationalities`,
        /// `address`) disclosures its members too.
        func collectSubtree(_ node: Any) {
            if let object = node as? [String: Any] {
                for digest in (object["_sd"] as? [String] ?? []) {
                    guard let disclosure = byDigest[digest] else { continue }
                    selected.insert(disclosure.encoded)
                    collectSubtree(disclosure.value)
                }
                for (key, value) in object where key != "_sd" {
                    collectSubtree(value)
                }
            } else if let array = node as? [Any] {
                for element in array {
                    if let digestObject = element as? [String: Any],
                       let digest = digestObject["..."] as? String {
                        guard let disclosure = byDigest[digest] else { continue }
                        selected.insert(disclosure.encoded)
                        collectSubtree(disclosure.value)
                    } else {
                        collectSubtree(element)
                    }
                }
            }
        }

        func walk(_ node: Any, remaining: ArraySlice<String>) {
            guard let key = remaining.first else {
                collectSubtree(node)
                return
            }
            let rest = remaining.dropFirst()

            if let array = node as? [Any] {
                // A path segment never names an array index here (DCQL null and
                // integer indices both drop out), so the segment applies to every
                // element - resolving each element's disclosure on the way in.
                for element in array {
                    if let digestObject = element as? [String: Any],
                       let digest = digestObject["..."] as? String {
                        guard let disclosure = byDigest[digest] else { continue }
                        selected.insert(disclosure.encoded)
                        walk(disclosure.value, remaining: remaining)
                    } else {
                        walk(element, remaining: remaining)
                    }
                }
                return
            }

            guard let object = node as? [String: Any] else { return }

            // A claim the issuer left in the clear needs no disclosure of its own.
            if let child = object[key] {
                walk(child, remaining: rest)
                return
            }
            // Otherwise it is behind one of this node's digests.
            for digest in (object["_sd"] as? [String] ?? []) {
                guard let disclosure = byDigest[digest], disclosure.name == key else { continue }
                selected.insert(disclosure.encoded)
                walk(disclosure.value, remaining: rest)
                return
            }
        }

        for path in paths {
            walk(payload, remaining: path[...])
        }
        return Array(selected)
    }

    /// The issuer JWT payload with its digests still unresolved - the shape the
    /// path walk needs, since it is the `_sd` lists that say which disclosure
    /// belongs at which level.
    private func issuerPayload(from issuedJwt: String) -> [String: Any]? {
        let parts = issuedJwt.split(separator: ".")
        guard parts.count > 1, let json = String(parts[1]).decodeBase64() else { return nil }
        return try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
    }

    public func processDisclosuresWithDCQL(
        credential: String?,
        dcqlCredential: CredentialItems?, format: String?, keyHandler: SecureKeyProtocol) -> String? {
            guard let credential = credential, let dcqlData = dcqlCredential else { return nil }

            // Split the credential into disclosures and the issued JWT
            guard let disclosures = SDJWTService.shared.getDisclosuresFromSDJWT(credential), !disclosures.isEmpty,
                  let issuedJwt = SDJWTService.shared.getIssuerJwtFromSDJWT(credential) else {
                return SDJWTService.shared.getIssuerJwtFromSDJWT(credential)
            }

            // An absent `claims` is the Verifier asking for the whole credential.
            guard let claims = dcqlData.claims else { return issuedJwt }

            var requestedPaths: [[String]] = []
            for claim in claims {
                // A namespaced claim addresses an mdoc namespace, not an SD-JWT path.
                guard case .pathClaim(let pathClaim) = claim else { continue }
                let path = pathClaim.path.compactMap { $0 }
                guard !path.isEmpty else { continue }
                requestedPaths.append(path)
            }

            guard let payload = issuerPayload(from: issuedJwt) else { return issuedJwt }

            let selected = selectDisclosures(payload: payload, disclosures: disclosures, paths: requestedPaths)

            var presentation = issuedJwt
            for disclosure in selected {
                presentation += "~\(disclosure)"
            }
            return presentation.isEmpty ? nil : presentation
        }
    
    public func processDisclosures(credential: String?,
                                   query: Any?, format: String?, keyHandler: SecureKeyProtocol) -> String? {
        if let inputDescriptor = query as? InputDescriptor {
            return processDisclosuresWithPresentationDefinition(credential: credential, inputDescriptor: inputDescriptor, format: format, keyHandler: keyHandler)
        } else if let dcql = query as? CredentialItems {
            return processDisclosuresWithDCQL(credential: credential, dcqlCredential: dcql, format: format, keyHandler: keyHandler)
        } else {
            return nil
        }
    }
    
    public func updateIssuerJwtWithDisclosures(credential: String?) -> String? {
        guard let split = credential?.split(separator: "."), split.count > 1,
              let jsonString = "\(split[1])".decodeBase64(),
              let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) else { return nil }
        
        var object = jsonObject
        
        var hashList: [String] = []
        let disclosures = getDisclosuresFromSDJWT(credential) ?? []
        disclosures.forEach { encodedString in
            guard let hash = calculateSHA256Hash(inputString: encodedString) else { return }
            hashList.append(hash)
        }
        
        object = addDisclosuresToCredential(jsonElement: jsonObject, disclosures: disclosures, hashList: hashList)
        
        guard let jsonData = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return String(data: jsonData, encoding: .utf8)
    }
    public func updateIssuerJwtWithDisclosuresForFiltering(credential: String?) -> String? {
        guard let split = credential?.split(separator: "."), split.count > 1,
              let jsonString = "\(split[1])".decodeBase64(),
              let jsonObject = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) else { return nil }
        
        var object = jsonObject
        
        var hashList: [String] = []
        let disclosures = getDisclosuresFromSDJWT(credential) ?? []
        disclosures.forEach { encodedString in
            guard let hash = calculateSHA256Hash(inputString: encodedString) else { return }
            hashList.append(hash)
        }
        
        object = addDisclosuresToCredentialForFiltering(jsonElement: jsonObject, disclosures: disclosures, hashList: hashList)
        
        guard let jsonData = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return String(data: jsonData, encoding: .utf8)
    }
    private func addDisclosuresToCredentialForFiltering(jsonElement: [String: Any], disclosures: [String], hashList: [String]) -> [String: Any] {
        var modifiedJsonElement = jsonElement
        
        if modifiedJsonElement["_sd"] != nil {
            guard let sdList = modifiedJsonElement["_sd"] as? [String] else { return [:] }
            for (index, hash) in hashList.enumerated() {
                if isStringPresentInJSONArray(jsonArray: sdList, searchString: hash) {
                    
                    if let disclosure = disclosures[index].decodeBase64() {
                        let (decodedKey, decodedValue) = extractKeyValue(from: disclosure) ?? ("","" as Any)
                        if let decodedValue = decodedValue as? [String: Any] {
                            modifiedJsonElement[decodedKey] = disclosure
                        } else if let decodedValue = decodedValue as? [Any] {
                            modifiedJsonElement[decodedKey] = disclosure
                        } else {
                            modifiedJsonElement[decodedKey] = disclosure
                        }
                    }
                }
            }
        }
        
        for (key, value) in modifiedJsonElement {
            if(value is [String: Any]){
                modifiedJsonElement[key] = addDisclosuresToCredentialForFiltering(jsonElement: value as! [String : Any], disclosures: disclosures, hashList: hashList)
            }
        }
        
        return modifiedJsonElement
    }
    
    private func addDisclosuresToCredential(jsonElement: [String: Any], disclosures: [String], hashList: [String]) -> [String: Any] {
        var modifiedJsonElement = jsonElement
        
        if modifiedJsonElement["_sd"] != nil {
            guard let sdList = modifiedJsonElement["_sd"] as? [String] else { return [:] }
            for (index, hash) in hashList.enumerated() {
                if isStringPresentInJSONArray(jsonArray: sdList, searchString: hash) {
                    
                    if let disclosure = disclosures[index].decodeBase64() {
                        let (decodedKey, decodedValue) = extractKeyValue(from: disclosure) ?? ("", "" as Any)
                        if let decodedValue = decodedValue as? [String: Any] {
                            modifiedJsonElement[decodedKey] = decodedValue as Any
                        } else if let decodedValue = decodedValue as? [Any] {
                            modifiedJsonElement[decodedKey] = decodedValue as Any
                        } else {
                            modifiedJsonElement[decodedKey] = decodedValue
                        }
                    }
                }
            }
        }
        
        // Handle array fields with {"...": hash} digest elements
        var keysToUpdate: [String: [Any]] = [:]
        
        for (key, value) in modifiedJsonElement {
            if let arrayValue = value as? [Any] {
                // Check if any element in the array is a digest object {"...": hash}
                let hasDigestElements = arrayValue.contains { element in
                    if let obj = element as? [String: Any] {
                        return obj["..."] != nil
                    }
                    return false
                }
                
                if hasDigestElements {
                    var resolvedArray: [Any] = []
                    
                    for arrayElement in arrayValue {
                        if let digestObject = arrayElement as? [String: Any],
                           let digestValue = digestObject["..."] as? String {
                            // Find matching hash in hashList
                            if let matchIndex = hashList.firstIndex(of: digestValue) {
                                if let disclosure = disclosures[matchIndex].decodeBase64() {
                                    // Array element disclosure format: [salt, value]
                                    if let disclosureArray = parseJSONArray(from: disclosure),
                                       disclosureArray.count > 1 {
                                        resolvedArray.append(disclosureArray[1])
                                    }
                                }
                                // If decoding fails, omit element (not disclosed)
                            }
                            // If no match found, omit (not disclosed)
                        } else {
                            // Plain element — recurse if object, keep as-is otherwise
                            if let nestedObject = arrayElement as? [String: Any] {
                                let resolved = addDisclosuresToCredential(
                                    jsonElement: nestedObject,
                                    disclosures: disclosures,
                                    hashList: hashList
                                )
                                resolvedArray.append(resolved)
                            } else {
                                resolvedArray.append(arrayElement)
                            }
                        }
                    }
                    
                    keysToUpdate[key] = resolvedArray
                } else {
                    // No digest elements — recurse into each object element (existing behavior)
                    let resolvedArray = arrayValue.map { element -> Any in
                        if let nestedObject = element as? [String: Any] {
                            return addDisclosuresToCredential(
                                jsonElement: nestedObject,
                                disclosures: disclosures,
                                hashList: hashList
                            )
                        }
                        return element
                    }
                    keysToUpdate[key] = resolvedArray
                }
            } else if let nestedObject = value as? [String: Any] {
                // Recurse into nested objects (existing behavior)
                modifiedJsonElement[key] = addDisclosuresToCredential(
                    jsonElement: nestedObject,
                    disclosures: disclosures,
                    hashList: hashList
                )
            }
        }
        
        // Apply resolved arrays back to the object
        for (key, resolvedArray) in keysToUpdate {
            modifiedJsonElement[key] = resolvedArray
        }
        
        return modifiedJsonElement
    }

    // Helper to parse a JSON string into an array
    private func parseJSONArray(from jsonString: String) -> [Any]? {
        guard let data = jsonString.data(using: .utf8),
              let array = try? JSONSerialization.jsonObject(with: data) as? [Any] else {
            return nil
        }
        return array
    }
    
    private func isStringPresentInJSONArray(jsonArray: [String], searchString: String) -> Bool {
        for element in jsonArray {
            if element == searchString {
                return true
            }
        }
        return false
    }
    private func extractKeyValue(from decodedString: String) -> (String, Any)? {
        guard let jsonArray = try? JSONSerialization.jsonObject(with: Data(decodedString.utf8)) as? [Any],
              jsonArray.count >= 3,
              let key = jsonArray[1] as? String,
              let value = jsonArray[2] as? Any else {
            return nil
        }
        return (key, value)
    }
    public func getDisclosuresFromSDJWT(_ credential: String?) -> [String]? {
        guard let split = credential?.split(separator: "~"), split.count > 1 else {
            return []
        }
        return split.dropFirst().map { String($0) }
    }
    public func getIssuerJwtFromSDJWT(_ credential: String?) -> String? {
        guard let split = credential?.split(separator: "~"), let first = split.first else {
            return nil
        }
        return String(first)
    }
}
