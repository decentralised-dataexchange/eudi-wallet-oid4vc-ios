//Class implementing the high level key generation and signing of data
//using JOSESwift library for secure enclave

import Foundation
import Security
import JOSESwift


enum SecureEnclaveError: Error {
    case couldNotLoadKeyPair
    case couldNotGenerateKeyPair(description: String)
    case couldNotCreateSigner
    case couldNotCreateVerifier
}

class SecureEnclave {
    let keyPair: KeyPair

    init(privateKeyApplicationTag: String) {
        do {
            keyPair = try SecureEnclave.loadKeyPair(with: privateKeyApplicationTag)
        } catch {
            keyPair = try! SecureEnclave.generateKeyPair(with: privateKeyApplicationTag)
        }
    }

    //signing of data securely with the private key
    func sign(_ message: String, header: Data) throws -> String {
        if let headerParams = JWSHeader(header){
            let payload = Payload(message.data(using: .utf8)!)

            guard let signer = Signer(signatureAlgorithm: .ES256, key: keyPair.privateKey) else {
                throw SecureEnclaveError.couldNotCreateSigner
            }

            return try JWS(header: headerParams, payload: payload, signer: signer).compactSerializedString
        }else{
            throw SecureEnclaveError.couldNotCreateSigner
        }
    }

    func verify(_ compactSerialization: String) throws -> Bool {
        guard let verifier = Verifier(signatureAlgorithm: .ES256, key: keyPair.publicKey) else {
            throw SecureEnclaveError.couldNotCreateVerifier
        }

        let jws = try JWS(compactSerialization: compactSerialization)

        return jws.isValid(for: verifier)
    }

}

extension SecureEnclave {
    typealias KeyPair = (privateKey: SecKey, publicKey: SecKey)

    //Load the private and public keys if already available in secure enclave
    /// Load the Secure Enclave key stored under `applicationTag`.
    ///
    /// The tag is passed as a String, where the Security framework wants Data.
    /// A query built that way does not reliably constrain the search, so
    /// SecItemCopyMatching with the default kSecMatchLimitOne can answer with
    /// some other Secure Enclave key entirely - and a lookup for a brand new
    /// label then *succeeds*, handing back an existing key instead of letting
    /// the caller create one. Keys silently share material, and a credential
    /// gets signed by a key that is not the one being attested.
    ///
    /// Rather than change how keys are written - which would re-address every
    /// key already in the Keychain and strand credentials that are already
    /// issued - every candidate is fetched and the tag is checked here. Storage
    /// is untouched; only the matching becomes exact.
    static func loadKeyPair(with applicationTag: String) throws -> KeyPair {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let candidates = item as? [[String: Any]] else {
            throw SecureEnclaveError.couldNotLoadKeyPair
        }

        let wanted = Data(applicationTag.utf8)
        let match = candidates.first { entry in
            switch entry[kSecAttrApplicationTag as String] {
            case let data as Data:     return data == wanted
            case let text as String:   return text == applicationTag
            default:                   return false
            }
        }
        guard let match = match, let privateKey = match[kSecValueRef as String] else {
            throw SecureEnclaveError.couldNotLoadKeyPair
        }

        let key = privateKey as! SecKey
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw SecureEnclaveError.couldNotLoadKeyPair
        }
        return (key, publicKey)
    }

    //generate new pair of public and private keys from secure enclave
    static func generateKeyPair(with applicationTag: String) throws -> KeyPair {
        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil
        )!

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag,
                kSecAttrAccessControl as String: access
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw SecureEnclaveError.couldNotGenerateKeyPair(
                description: error!.takeRetainedValue().localizedDescription
            )
        }

        let publicKey = SecKeyCopyPublicKey(privateKey)!
        
        return (privateKey, publicKey)
    }
    
    //create jason web key for the given public key
    func getJWK(publicKey:Data) -> [String:Any]?{
        let jwk = try! ECPublicKey(publicKey: publicKey)
        if let jsonData = jwk.jsonData(){
            if let jwkDict = convertToDictionary(data: jsonData){
                return jwkDict
            }
        }
        return nil
    }
    
    func convertToDictionary(data: Data) -> [String: Any]? {
      
           do {
               return try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
           } catch {
               print(error.localizedDescription)
           }
       
       return nil
   }
}
