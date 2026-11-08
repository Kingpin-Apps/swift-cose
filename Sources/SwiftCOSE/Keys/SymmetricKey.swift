import Foundation


public class CoseSymmetricKey: CoseKey {
    public var optionalParams: [AnyHashable: Any]
    
    // Mandatory SymKpK attribute (key)
    public var k: Data {
        get {
            guard let key = store[SymKpK()] as? Data else {
                fatalError("Symmetric COSE key must have the SymKpK attribute")
            }
            return key
        }
        set {
            guard CoseSymmetricKey.validKeyLengths.contains(newValue.count) else {
                fatalError("Key length should be 16, 24, 32, 48 or 64 bytes")
            }
            store[SymKpK()] = newValue
        }
    }

    /// Key sizes for AES (16, 24, 32 bytes) and HMAC with SHA-256, SHA-384
    /// and SHA-512 (32, 48, 64 bytes).
    static let validKeyLengths: Set<Int> = [16, 24, 32, 48, 64]

    // Supported key operations
    public override class var supportedKeyOps: [KeyOps.Type] {
        [MacCreateOp.self, MacVerifyOp.self, EncryptOp.self, DecryptOp.self, UnwrapOp.self, WrapOp.self]
    }
    
    // MARK: - Initialization Methods
    
    /// Create an COSE CoseSymmetricKey.
    /// - Parameters:
    ///   - k: Symmetric Key value.
    ///   - optionalParams: A dictionary with optional key parameters.
    public init(k: Data, optionalParams: [AnyHashable: Any] = [:]) throws {
        var transformedDict: [AnyHashable: Any] = [KpKty(): KtySymmetric()]
        
        // Transform optional parameters
        for (key, value) in optionalParams {
            let kp = try SymmetricKeyParam.fromId(for: key)
            if kp is KpKeyOps {
                transformedDict[kp] = try CoseKey.parseKeyOps(value, for: CoseSymmetricKey.self)
                continue
            }
            if let parser = kp.valueParser {
                if let value = value as? Array<Any> {
                    for (_, v) in value.enumerated() {
                        transformedDict[kp] = try parser(v)
                    }
                } else {
                    transformedDict[kp] = try parser(value)
                }
            } else {
                transformedDict[kp] = value
            }
        }
        
        // Validate key type
        guard let ktyValue = transformedDict[KpKty()] as? CoseAttribute, ktyValue == KtySymmetric() else {
            throw CoseError.invalidKey("Illegal key type in Symmetric COSE Key: \(String(describing: transformedDict[KpKty()]))")
        }
        
        self.optionalParams = optionalParams
        
        // Check here so a bad length (for example an unwrapped key from a
        // received message) throws instead of reaching the trapping setter.
        guard CoseSymmetricKey.validKeyLengths.contains(k.count) else {
            throw CoseError.invalidKey("Key length should be 16, 24, 32, 48 or 64 bytes")
        }
        
        super.init(keyDict: transformedDict)
        
        self.k = k
    }
    
    // MARK: - Methods
    
    /// Returns an initialized COSE Key object of type CoseSymmetricKey.
    /// - Parameter coseKey: Dictionary containing COSE Key parameters and there values.
    /// - Returns: An initialized CoseSymmetricKey key
    public override static func fromDictionary(_ coseKey: [AnyHashable: Any]) throws -> CoseSymmetricKey {
        let k = CoseKey.extractFromDict(coseKey, parameter: SymKpK())
        
        var optionalParams: [AnyHashable : Any] = coseKey
        CoseKey.removeFromDict(&optionalParams, parameter: SymKpK())
        
        guard let kBytes = k as? Data else {
            throw CoseError.invalidKey("A symmetric COSE key needs a byte string k")
        }
        return try CoseSymmetricKey(
            k: kBytes,
            optionalParams: optionalParams
        )
        
    }
    
    /// Generate a random Symmetric COSE key object.
    /// - Parameters:
    ///   - keyLength: Symmetric key length in bytes: 16, 24, 32, 48 or 64.
    ///   - optionalParams: Optional key attributes for the `SymmetricKey` object, e.g., `KpAlg` or  `KpKid`.
    /// - Returns: A COSE_key of type SymmetricKey.
    /// - Throws: `CoseError` if key length is invalid.
    public static func generateKey(keyLength: Int, optionalParams: [AnyHashable: Any]? = nil) throws -> CoseSymmetricKey {
        guard validKeyLengths.contains(keyLength) else {
            throw CoseError.invalidKey("Key length must be 16, 24, 32, 48 or 64 bytes")
        }
        let keyData = Data.randomBytes(count: keyLength)
        return try CoseSymmetricKey(
            k: keyData,
            optionalParams: optionalParams ?? [:]
        )
    }
    
    // Function to delete a key
    func delete(key: AnyHashable) throws {
        if let key = key as? SymmetricKeyParam {
            return try delete(key: key.identifier)
        } else {
            let transformedKey = try SymmetricKeyParam.fromId(for: key)
            
            if transformedKey != KpKty() && transformedKey != SymKpK() {
                store.removeValue(forKey: key)
                return
            }
        }

        throw CoseError
            .invalidKey(
                "Deleting \(key) attribute would lead to an invalid COSE Symmetric Key"
            )
    }
    
    // Representation
    public override var description: String {
        var keyRepresentation = keyRepr()
        
        if let key = keyRepresentation[SymKpK()] as? Data, !key.isEmpty {
            keyRepresentation[SymKpK()] = truncate(
                key.base64EncodedString()
            )
        }
        
        return "<COSE_Key(Symmetric): \(keyRepresentation)>"
    }
}
