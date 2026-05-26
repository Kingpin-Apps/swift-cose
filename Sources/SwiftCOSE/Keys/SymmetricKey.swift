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
            guard newValue.count == 16 || newValue.count == 24 || newValue.count == 32 else {
                fatalError("Key length should be either 16, 24, or 32 bytes")
            }
            store[SymKpK()] = newValue
        }
    }

    // Supported key operations
    private var _keyOps: [KeyOps] = []
    public override var keyOps: [KeyOps] {
        get {
            return store[KpKeyOps()] as? [KeyOps] ?? []
        }
        set {
            let supportedOps: [KeyOps.Type] = [
                MacCreateOp.self,
                MacVerifyOp.self,
                EncryptOp.self,
                DecryptOp.self,
                UnwrapOp.self,
                WrapOp.self
            ]
            
            for ops in newValue {
                // Check if the operation is supported by the key type
                guard supportedOps.contains(where: { $0 == type(of: ops) }) else {
                    fatalError("Invalid COSE key operation \(ops) for key type \(CoseSymmetricKey.self)")
                }
            }
            _keyOps = newValue
        }
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
        guard transformedDict[KpKty()] as! CoseAttribute == KtySymmetric() else {
            throw CoseError.invalidKey("Illegal key type in Symmetric COSE Key: \(String(describing: transformedDict[KpKty()]))")
        }
        
        self.optionalParams = optionalParams
        
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
        
        return try CoseSymmetricKey(
            k: k as! Data,
            optionalParams: optionalParams
        )
        
    }
    
    /// Generate a random Symmetric COSE key object.
    /// - Parameters:
    ///   - keyLen: Symmetric key length in bytes, must be of size 16, 24 or 32.
    ///   - optionalParams: Optional key attributes for the `SymmetricKey` object, e.g., `KpAlg` or  `KpKid`.
    /// - Returns: A COSE_key of type SymmetricKey.
    /// - Throws: `CoseError` if key length is invalid.
    public static func generateKey(keyLength: Int, optionalParams: [AnyHashable: Any]? = nil) throws -> CoseSymmetricKey {
        guard keyLength == 16 || keyLength == 24 || keyLength == 32 else {
            throw CoseError.invalidKey("Key length must be 16, 24, or 32 bytes")
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
