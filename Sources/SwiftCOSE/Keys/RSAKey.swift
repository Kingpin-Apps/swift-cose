import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import CryptoSwift

public class RSAKey: CoseKey {
    var other: [[String: Any]] = []
    var r_i: Data?
    var d_i: Data?
    var t_i: Data?
    var optionalParams: [AnyHashable: Any] = [:]
    
    // MARK: - n Property
    var n: Data? {
        get {
            return store[RSAKpN()] as? Data ?? nil
        }
        set {
            store[RSAKpN()] = newValue
        }
    }
    
    // MARK: - e Property
    var e: Data? {
        get {
            return store[RSAKpE()] as? Data ?? nil
        }
        set {
            store[RSAKpE()] = newValue
        }
    }
    
    // MARK: - d Property
    var d: Data? {
        get {
            return store[RSAKpD()] as? Data ?? nil
        }
        set {
            store[RSAKpD()] = newValue
        }
    }
    
    // MARK: - p Property
    var p: Data? {
        get {
            return store[RSAKpP()] as? Data ?? nil
        }
        set {
            store[RSAKpP()] = newValue
        }
    }
    
    // MARK: - q Property
    var q: Data? {
        get {
            return store[RSAKpQ()] as? Data ?? nil
        }
        set {
            store[RSAKpQ()] = newValue
        }
    }
    
    // MARK: - dp Property
    var dp: Data? {
        get {
            return store[RSAKpDP()] as? Data ?? nil
        }
        set {
            store[RSAKpDP()] = newValue
        }
    }
    
    // MARK: - dq Property
    var dq: Data? {
        get {
            return store[RSAKpDQ()] as? Data ?? nil
        }
        set {
            store[RSAKpDQ()] = newValue
        }
    }

    
    // MARK: - qInv Property
    var qInv: Data? {
        get {
            return store[RSAKpQInv()] as? Data ?? nil
        }
        set {
            store[RSAKpQInv()] = newValue
        }
    }
    
    // MARK: - Key Operations
    private var _keyOps: [KeyOps] = []
    
    public override var keyOps: [KeyOps] {
        get {
            return _keyOps as [KeyOps]
        }
        set {
            let supportedOps: [KeyOps.Type] = [
                SignOp.self,
                VerifyOp.self,
                DeriveKeyOp.self,
                DeriveBitsOp.self
            ]
            
            for ops in newValue {
                // Check if the operation is supported by the key type
                guard supportedOps.contains(where: { $0 == type(of: ops) }) else {
                    fatalError("Invalid COSE key operation \(ops) for key type \(RSAKey.self)")
                }
            }
            _keyOps = newValue 
        }
    }
    
    // MARK: - Initialization Methods
    init(
        n: Data? = nil,
        e: Data? = nil,
        d: Data? = nil,
        p: Data? = nil,
        q: Data? = nil,
        dp: Data? = nil,
        dq: Data? = nil,
        qInv: Data? = nil,
        other: [[String: Any]] = [],
        r_i: Data? = nil,
        d_i: Data? = nil,
        t_i: Data? = nil,
        optionalParams: [AnyHashable: Any] = [:]
    ) throws {
        var transformedDict: [AnyHashable: Any] = [KpKty(): KtyRSA()]
        
        let isPublicKey = !n!.isEmpty && !e!.isEmpty && ((d?.isEmpty) != nil) && p == nil && q == nil && dp == nil && dq == nil && qInv == nil && other.isEmpty && ((r_i?.isEmpty) != nil) && ((d_i?.isEmpty) != nil) && (
            (t_i?.isEmpty) != nil
        )

        let isPrivateKeyTwoPrimes = !n!.isEmpty && !e!.isEmpty && !d!.isEmpty && p != nil && q != nil && dp != nil && dq != nil && qInv != nil && other.isEmpty && r_i!.isEmpty && d_i!.isEmpty && t_i!.isEmpty

        let isPrivateKeyMultiplePrimes = !n!.isEmpty && !e!.isEmpty && !d!.isEmpty && p != nil && q != nil && dp != nil && dq != nil && qInv != nil && !other.isEmpty && !r_i!.isEmpty && !d_i!.isEmpty && !t_i!.isEmpty

        guard isPublicKey || isPrivateKeyTwoPrimes || isPrivateKeyMultiplePrimes else {
            throw CoseError.invalidKey("Invalid RSA key")
        }
        
        // Validate key type
        guard transformedDict[KpKty()] as! CoseAttribute == KtyRSA() else {
            throw CoseError.invalidKey("Illegal key type in RSA COSE Key: \(String(describing: transformedDict[KpKty()]))")
        }
        
        // Transform optional parameters
        for (key, value) in optionalParams {
            let kp = try RSAKeyParam.fromId(for: key)
            if let parser = kp.valueParser {
                transformedDict[kp] = try parser(value)
            } else {
                transformedDict[kp] = value
            }
        }
        
        self.optionalParams = transformedDict
        
        super.init(keyDict: transformedDict)

        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.qInv = qInv
        self.other = other
        self.r_i = r_i
        self.d_i = d_i
        self.t_i = t_i
        self.optionalParams = optionalParams
    }
    
    // MARK: - Methods
    
    /// Returns an initialized COSE Key object of type `RSAKey`.
    /// - Parameters:
    ///   - extKey: The external RSA key object.
    ///   - optionalParams: The optional parameters.
    /// - Returns: An initialized `RSAkey`
    public static func fromCryptographyKey(extKey: RSA, optionalParams: [AnyHashable: Any]) throws -> RSAKey {
        
        let n: BigUInteger = extKey.n
        let e: BigUInteger = extKey.e
        let d: BigUInteger? = extKey.d
        
        var coseKey: [AnyHashable : Any] = [
            RSAKpE(): toBstr(e),
            RSAKpN(): toBstr(n),
        ] as! [AnyHashable : Any]
        
        if let d = d { coseKey[RSAKpD()] = toBstr(d) }
        
        // Merge optional params
        for (key, value) in optionalParams {
            coseKey[key] = value
        }

        // Initialize RSAKey from dictionary
        return try RSAKey.fromDictionary(coseKey)
    }
    
    /// Generate a random RSAKey COSE key object. The RSA keys have two primes (see section 4 of RFC 8230).
    /// - Parameters:
    ///  - keyBits: The key length in bits.
    ///  - optionalParams: The optional parameters.
    /// - Returns: A COSE `RSAKey` key.
    static func generateKey(keyBits: Int, optionalParams: [AnyHashable: Any] = [:]) throws -> RSAKey {
        guard keyBits % 8 == 0 else {
            throw CoseError.invalidKey("Invalid key length")
        }
        
        // Generate prime numbers
        let p = try BigUInteger.getPrime(keyBits / 2)!
        let q = try BigUInteger.getPrime(keyBits / 2)!
        
        // Calculate modulus
        let n = p * q

        // Calculate public and private exponent
        let e: BigUInteger = 65537
        let phi = (p - 1) * (q - 1)
        guard let d = e.inverse(phi) else {
          throw RSA.Error.invalidInverseNotCoprimes
        }

        let extKey = try CryptoSwift.RSA(n: n, e: e, d: d, p: p, q: q)
        
        var additionalParams: [AnyHashable : Any] = [
            RSAKpP():toBstr(p),
            RSAKpQ():toBstr(q),
        ] as! [AnyHashable : Any]
        
        // Merge optional params
        for (key, value) in optionalParams {
            additionalParams[key] = value
        }

        return try RSAKey.fromCryptographyKey(
            extKey: extKey,
            optionalParams: additionalParams
        )
    }
    
    /// Returns an initialized COSE Key object of type RSAKey.
    /// - Parameter coseKey: Dict containing COSE Key parameters and there values.
    /// - Returns: An initialized RSAKey key.
    public override static func fromDictionary(_ coseKey: [AnyHashable: Any]) throws -> RSAKey {
        let e = CoseKey.extractFromDict(coseKey, parameter: RSAKpE())
        let n = CoseKey.extractFromDict(coseKey, parameter: RSAKpN())
        let d = CoseKey.extractFromDict(coseKey, parameter: RSAKpD())
        let p = CoseKey.extractFromDict(coseKey, parameter: RSAKpP())
        let q = CoseKey.extractFromDict(coseKey, parameter: RSAKpQ())
        let dp = CoseKey.extractFromDict(coseKey, parameter: RSAKpDP())
        let dq = CoseKey.extractFromDict(coseKey, parameter: RSAKpDQ())
        let qInv = CoseKey.extractFromDict(coseKey, parameter: RSAKpQInv())
        let other = CoseKey.extractFromDict(
            coseKey,
            parameter: RSAKpOther(),
            defaultValue: []
        )
        let r_i = CoseKey.extractFromDict(coseKey, parameter: RSAKpRi())
        let d_i = CoseKey.extractFromDict(coseKey, parameter: RSAKpDi())
        let t_i = CoseKey.extractFromDict(coseKey, parameter: RSAKpTi())
        
        var optionalParams: [AnyHashable : Any] = coseKey
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpE())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpN())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpD())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpP())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpQ())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpDP())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpDQ())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpQInv())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpOther())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpRi())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpDi())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpTi())
        
        return try RSAKey(
            n: n as? Data,
            e: e as? Data,
            d: d as? Data,
            p: p as? Data,
            q: q as? Data,
            dp: dp as? Data,
            dq: dq as? Data,
            qInv: qInv as? Data,
            other: other as! [[String: Any]],
            r_i: r_i as? Data,
            d_i: d_i as? Data,
            t_i: t_i as? Data,
            optionalParams: optionalParams as! [String : Any]
        )
    }
    
    
    // Function to delete a key
    func delete(key: AnyHashable) throws {
        if let key = key as? RSAKeyParam {
            return try delete(key: key.identifier)
        } else {
            let transformedKey = try RSAKeyParam.fromId(for: key)
            store.removeValue(forKey: transformedKey as AnyHashable)
            return
        }
    }
    
    // MARK: - Helpers
    
    public static func supportsCryptographyKeyType(_ key: Any) -> Bool {
        let supportedKeyTypes: [Any] = [
            RSA.self,
        ]
        
        return supportedKeyTypes.contains(where: { $0 as? any Any.Type == type(of: key) })
    }
    
    // Custom description for the object
    public override var description: String {
        let keyRepresentation = keyRepr()

        return "<COSE_Key(RSAKey): \(keyRepresentation)>"
    }
}
