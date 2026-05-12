import Foundation
import PotentCBOR
import PotentCodables
import OrderedCollections

/// Abstract base class for all COSE key types.
public class CoseKey: CustomStringConvertible {
    
    // MARK: - Abstract Properties
    public var description: String {
        let keyRepresentation = keyRepr()

        return "<COSE_Key: \(keyRepresentation)>"
    }

    // MARK: - Properties
    public var store: [AnyHashable: Any] = [:]
    private var keyTypes: [String: CoseKey] = [:]
    private var key: CoseKey?
    
    public var keyOps: [KeyOps] {
        get {
            let value = store.first(where: {
                $0.key == KpKeyOps() as AnyHashable || $0.key == KpKeyOps().identifier as AnyHashable || $0.key == KpKeyOps().fullname as AnyHashable
            })?.value
            
            if let value = value {
                return (value as! Array<Any>).map {
                    try! KeyOps.fromId(for: $0)
                }
            }
            return []
        }
        set {
            store[KpKeyOps()] = newValue
        }
    }
    
    public var kty: KTY? {
        get {
            let value = store.first(where: {
                $0.key == KpKty() as AnyHashable || $0.key == KpKty().identifier as AnyHashable || $0.key == KpKty().fullname as AnyHashable
            })?.value
            
            if let value = value {
                return try! KTY.fromId(for: value)
            }
            return nil
        }
        set {
            store[KpKty()] = newValue
        }
    }
    
    public var alg: CoseAlgorithm? {
        get {
            let value = store.first(where: {
                $0.key == KpAlg() as AnyHashable || $0.key == KpAlg().identifier as AnyHashable || $0.key == KpAlg().fullname as AnyHashable
            })?.value
            
            if let value = value {
                return try! CoseAlgorithm.fromId(for: value)
            }
            return nil
        }
        set {
            store[KpAlg()] = newValue
        }
    }
    
    public var kid: Data? {
        get {
            return store
                .first(where: { $0.key == KpKid() as AnyHashable || $0.key == KpKid().identifier as AnyHashable || $0.key == KpKid().fullname as AnyHashable })?.value as? Data
        }
        set {
            store[KpKid()] = newValue
        }
    }
    
    public var baseIV: Data? {
        get {
            return store
                .first(where: { $0.key == KpBaseIV() as AnyHashable || $0.key == KpBaseIV().identifier as AnyHashable || $0.key == KpBaseIV().fullname as AnyHashable })?.value as? Data
        }
        set {
            store[KpBaseIV()] = newValue
        }
    }
    
    // MARK: - Initialization
    public init(keyDict: [AnyHashable: Any]) {
        self.store = keyDict
        if keyDict[KpKeyOps()] != nil {
            self.store.removeValue(forKey: KpKeyOps())
        }
    }
    
    // MARK: - Methods
    /// Returns the appropriate `CoseKey` instance for the given identifier or name.
    /// - Parameter attribute: The identifier or name of the key type.
    /// - Returns: A specific `CoseKey` instance.
    public static func fromId(for attribute: Any) throws -> CoseKey.Type {
       switch attribute {
           case let id as any BinaryInteger:
               // If the identifier is an Int, convert it to KeyTypeIdentifier
               guard let type = KeyTypeIdentifier(rawValue: Int(id)) else {
                   throw CoseError.invalidKeyType("Unknown type identifier")
               }
               return getInstance(for: type)

           case let name as String:
               // If the identifier is a String, attempt to match it to a KeyTypeIdentifier
               guard let type = KeyTypeIdentifier.fromFullName(name) else {
                   throw CoseError.invalidKeyType("Unknown type fullname")
               }
               return getInstance(for: type)

           case let type as KeyTypeIdentifier:
               // If the identifier is already a KeyTypeIdentifier, get the instance directly
               return getInstance(for: type)

           case let attr as CoseAttribute:
               let type = try KeyTypeIdentifier.fromKTY(attr as! KTY)
               return getInstance(for: type)

           default:
               throw CoseError.invalidKeyType("Unsupported identifier type. Must be Int, String, or KeyTypeIdentifier")
       }
   }
    
    /// Return the key type identifier.
    /// - Parameter identifier: The identifier to return.
    /// - Returns: The key type identifier.
    public static func getInstance(for identifier: KeyTypeIdentifier) -> CoseKey.Type {
        switch identifier {
            case .reserved:
                return ReservedKey.self
            case .okp:
                return OKPKey.self
            case .ec2:
                return EC2Key.self
            case .rsa:
                return RSAKey.self
            case .symmetric:
                return CoseSymmetricKey.self
        }
    }
    
    // MARK: - Base64 Encoding/Decoding
    public static func base64decode(_ input: String) -> Data? {
        var normalizedInput = input.replacingOccurrences(of: "-", with: "+")
                                   .replacingOccurrences(of: "_", with: "/")
        switch normalizedInput.count % 4 {
        case 0:
            break
        case 2:
            normalizedInput += "=="
        case 3:
            normalizedInput += "="
        default:
            return nil
        }
        return Data(base64Encoded: normalizedInput)
    }
    
    public static func base64encode(_ data: Data) -> String {
        return data.base64EncodedString()
    }
    
    // MARK: - Encode and Decode
    public func encode() throws -> Data? {
        // Convert `store` dictionary into a CBOR-compatible map
        let cborCompatibleMap = try store.reduce(into: OrderedDictionary<CBOR, CBOR>()) { result, entry in
            var key: CBOR
            var value: CBOR

            if let stringKey = entry.key as? String {
                key = CBOR(stringKey)
            } else if let intKey = entry.key as? Int {
                key = CBOR(intKey)
            } else if let coseAttr = entry.key as? CoseAttribute {
                if let identifier = coseAttr.identifier {
                    key = CBOR(identifier)
                } else if let fullName = coseAttr.fullname {
                    key = CBOR(fullName)
                } else {
                    throw CoseError.invalidKeyType("Unsupported key type: \(type(of: entry.key))")
                }
            } else {
                throw CoseError.invalidKeyType("Unsupported key type: \(type(of: entry.key))")
            }

            if let stringValue = entry.value as? String {
                value = CBOR(stringValue)
            } else if let intValue = entry.value as? Int {
                value = CBOR(intValue)
            } else if let coseAttr = entry.value as? CoseAttribute {
                if let identifier = coseAttr.identifier {
                    value = CBOR(identifier)
                } else if let fullName = coseAttr.fullname {
                    value = CBOR(fullName)
                } else {
                    throw CoseError.invalidKeyType("Unsupported key type: \(type(of: entry.key))")
                }
            } else if let data = entry.value as? Data {
                value = CBOR(data)
            } else {
                throw CoseError.invalidKeyType("Unsupported value type: \(type(of: entry.value))")
            }
            result[key] = value
        }
        
        // Serialize the CBOR map into Data
        return try? CBORSerialization.data(from: .map(cborCompatibleMap))
    }
    
    /// Decodes a CBOR-encoded COSE key object.
    /// - Parameter received: A CBOR-encoded bytestring.
    /// - Returns: An initialized COSE key.
    public static func decode(_ received: Data) throws -> CoseKey? {
        let cbor = try CBORSerialization.cbor(from: received)
        let mapValue = cbor.mapValue ?? [:]
        let dict = mapValue.reduce(into: [AnyHashable: Any]()) { result, entry in
            let k = entry.key.unwrapped!
            let v = entry.value.unwrapped!
            
            result[k as! AnyHashable] = v
        }
        return try fromDictionary(dict)
    }
    
    /// Initialize a COSE key from a dictionary.
    /// - Parameter received: Dictionary to translate to COSE key.
    /// - Returns: An initialized COSE Key object.
    public class func fromDictionary(_ received: [AnyHashable: Any]) throws -> CoseKey {
        // Attempt to initialize a COSE key from the dictionary
        let kpKty = KpKty()
        let kpKtyToUse = received[kpKty] ?? received[kpKty.identifier] ?? received[kpKty.fullname]
        
        guard kpKtyToUse != nil else {
            throw CoseError.invalidKeyType("Failed to determine key type")
        }
        
        do {
            let keyTypeClass = try fromId(for: kpKtyToUse!)
            return try keyTypeClass.fromDictionary(received)
        } catch {
            throw CoseError.invalidKeyType("Failed to determine key type. \(error.localizedDescription)")
        }
    }
    
    /// Initializes a COSE key from a PEM-encoded private key.
    /// - Parameters:
    ///   - pem: PEM-encoded private key as a String.
    ///   - password: Optional password to decrypt the key.
    ///   - optionalParams: Optional parameters to add to the key.
    /// - Throws: CoseError if the key cannot be loaded.
    /// - Returns: An initialized `CoseKey` object.
    public static func fromPEMPrivateKey(pem: String,
                                         password: Data? = nil,
                                         optionalParams: [String: Any]? = nil) throws -> CoseKey {
        // Load the PEM private key
        guard let privateKey = try? loadPEMPrivateKey(pem: pem, password: password) else {
            throw CoseError.invalidKeyType("Failed to load PEM private key")
        }
        
        // Convert to COSE key
        return try CoseKey.fromCryptographyKey(privateKey, optionalParams: optionalParams)
    }
    
    /// Initializes a COSE key from a PEM-encoded public key.
    /// - Parameters:
    ///   - pem: PEM-encoded public key as a String.
    ///   - optionalParams: Optional parameters to add to the key.
    /// - Throws: CoseError if the key cannot be loaded.
    /// - Returns: An initialized `CoseKey` object.
    public static func fromPEMPublicKey(pem: String,
                                        optionalParams: [String: Any]? = nil) throws -> CoseKey {
        // Load the PEM public key
        guard let publicKey = try? loadPEMPublicKey(pem: pem) else {
            throw CoseError.invalidKeyType("Failed to load PEM public key")
        }
        
        // Convert to COSE key
        return try CoseKey.fromCryptographyKey(publicKey, optionalParams: optionalParams)
    }
    
    /// Initialize a COSE key from an external cryptographic key.
    ///
    /// - Parameters:
    ///   - extKey: A cryptographic key, which could be of different supported types.
    ///   - optionalParams: Optional parameters to be added to the key.
    /// - Throws: CoseError if no supported key type is found.
    /// - Returns: An initialized COSEKey object.
    public class func fromCryptographyKey(
        _ extKey: Any,
        optionalParams: [String: Any]? = nil
    ) throws -> CoseKey {
        // Iterate through registered key types
        do {
            let coseKey = try fromId(for: extKey)
            return try coseKey.fromCryptographyKey(extKey, optionalParams: optionalParams)
        } catch {
            throw CoseError.invalidKeyType("Unsupported key type: \(type(of: extKey))")
        }
    }
    
    public class func extractFromDict<T: KeyParam>(
        _ coseKey: [AnyHashable: Any],
        parameter: T,
        defaultValue: Any? = Data()
    ) -> Any {
        if let value = coseKey[parameter] {
            return value
        } else if let value = coseKey[parameter.identifier] {
            return value
        } else if let value = coseKey[parameter.fullname] {
            return value
        } else {
            return defaultValue as Any
        }
    }
    
    public class func removeFromDict<T: KeyParam>(
        _ coseKey: inout [AnyHashable: Any],
        parameter: T
    ) {
        coseKey.removeValue(forKey: parameter)
        coseKey.removeValue(forKey: parameter.identifier)
        coseKey.removeValue(forKey: parameter.fullname)
    }
    
    // MARK: - Store Methods
    // Subscript for getting values
    public subscript(key: Any) -> Any? {
        get {
            if let key = key as? KeyParam {
                return store[key]
            }
            return store[keyTransform(key)]
        }
        set {
            if let key = key as? KeyParam {
                store[key] = newValue
            } else {
                store[keyTransform(key)] = newValue
            }
        }
    }
    
    // Deletion method
    public func removeItem(forKey key: Any) {
        if let key = key as? KeyParam {
            store.removeValue(forKey: key)
        } else {
            store.removeValue(forKey: keyTransform(key))
        }
    }
    
    // Contains method
    public func contains(_ key: Any) -> Bool {
        if let key = key as? KeyParam {
            return store.keys.contains(key)
        } else {
            return store.keys.contains(keyTransform(key))
        }
    }
    
    // Length method
    public var count: Int {
        return store.count
    }
    
    // MARK: - Verification
    public func verify(keyType: CoseKey.Type, algorithm: CoseAlgorithm, keyOps: [KeyOps]) throws {
        guard type(of: self) == keyType else {
            throw CoseError.invalidKeyType("Invalid key type: \(type(of: self)) expected \(keyType)")
        }
        
        if let alg = self.alg, alg != algorithm {
            throw CoseError.invalidAlgorithm("Invalid algorithm: \(alg) expected \(algorithm)")
        }
        
        if !self.keyOps.isEmpty {
            let supportedOps = self.keyOps.map { $0 }
            let requestedOps = Set(keyOps)
            if !requestedOps.isSubset(of: supportedOps) {
                throw CoseError.invalidKeyOps("Invalid key operations")
            }
        }
    }
    
    // MARK: - Helper Methods
    public func keyRepr() -> [AnyHashable: Any] {
        var names: [String: Any] = [:]
        
        // Sorting keys and transforming the dictionary
        let sortedKeys = store.keys.sorted { (lhs, rhs) -> Bool in
            if let lhsIdentifiable = lhs as? CoseAttribute, let rhsIdentifiable = rhs as? CoseAttribute {
                return lhsIdentifiable < rhsIdentifiable
            }
            return false
        }
        
        for kp in sortedKeys {
            let keyName: String
            if let kpString = kp as? CoseKey {
                keyName = kpString.description
            } else {
                keyName = "\(kp)"
            }
            
            let value = store[kp]
            let valueName: String
            if let valueString = value as? CustomStringConvertible {
                valueName = valueString.description
            } else {
                valueName = "\(String(describing: value))"
            }
            
            names[keyName] = valueName
        }
        
        // Special handling for "KpKeyOps" key
        if let kpKeyOpsName = String(describing: KpKeyOps.self) as String?,
           var kpOpsList = names[kpKeyOpsName] as? [Any] {
            kpOpsList = kpOpsList.map { ops in
                if let opsString = ops as? CustomStringConvertible {
                    return opsString.description
                } else {
                    return "\(ops)"
                }
            }
            names[kpKeyOpsName] = kpOpsList
        }
        
        // Special handling for "BASE_IV" key
        if var baseIV = names["BASE_IV"] as? String, !baseIV.isEmpty {
            baseIV = truncate(baseIV)
            names["BASE_IV"] = baseIV
        }
        
        return names
    }
    
    /// Load a PEM-encoded private key
    private static func loadPEMPrivateKey(pem: String, password: Data?) throws -> Any {
        #if canImport(Security)
        let pemData = Data(pem.utf8)
        let options: [String: Any] = password != nil ? [kSecImportExportPassphrase as String: password!] : [:]

        var items: CFArray?
        let status = SecPKCS12Import(pemData as CFData, options as CFDictionary, &items)

        guard status == errSecSuccess, let array = items as? [[String: Any]], let identity = array.first?[kSecImportItemIdentity as String] else {
            throw CoseError.invalidKeyType("Invalid PEM format for private key.")
        }

        return identity
        #else
        throw CoseError.invalidKeyType("PEM private key loading via PKCS12 is not supported on this platform.")
        #endif
    }

    /// Load a PEM-encoded public key
    private static func loadPEMPublicKey(pem: String) throws -> Any {
        #if canImport(Security)
        let pemData = Data(pem.utf8)
        let options: [String: Any] = [:]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(pemData as CFData, options as CFDictionary, &error) else {
            throw CoseError.invalidKeyType("Invalid PEM format for public key.")
        }

        return secKey
        #else
        throw CoseError.invalidKeyType("PEM public key loading via SecKey is not supported on this platform.")
        #endif
    }
    
    private func keyTransform(_ key: Any) -> KeyParam? {
        do {
            return try KeyParam.fromId(for: key)
        } catch {
            return nil
        }
    }
}

public class ReservedKey: CoseKey {
    
    /// Initializes a COSE Key object of type ReservedKey.
    /// - Parameter keyDict: The dictionary containing COSE Key parameters and their values.
    public override init(keyDict: [AnyHashable: Any]) {
        super.init(keyDict: keyDict)
    }
    
    /// Returns an initialized COSE Key object of type ReservedKey.
    /// - Parameter coseKey: Dict containing COSE Key parameters and their values.
    /// - Returns: An initialized ReservedKey key
    public override class func fromDictionary(_ coseKey: [AnyHashable: Any]) throws -> ReservedKey {
        return ReservedKey(keyDict: coseKey)
    }
    
    // Custom description for the object
    public override var description: String {
        let keyRepresentation = keyRepr()

        return "<COSE_Key(ReservedKey): \(keyRepresentation)>"
    }
}
