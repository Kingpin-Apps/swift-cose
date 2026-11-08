import Foundation
import _CryptoExtras
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
    public override class var supportedKeyOps: [KeyOps.Type] {
        [SignOp.self, VerifyOp.self, DeriveKeyOp.self, DeriveBitsOp.self]
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
        
        // A component counts as present only when it is non-empty; nothing
        // here is force-unwrapped, so a malformed key throws instead of
        // trapping.
        func has(_ value: Data?) -> Bool { value.map { !$0.isEmpty } ?? false }
        guard has(n), has(e) else {
            throw CoseError.invalidKey("An RSA key needs n and e")
        }
        // A private key needs d, p and q; dP, dQ and qInv are optional,
        // as before (the primes are what the signer uses).
        let crt = [p, q, dp, dq, qInv].map(has)
        let primes = has(p) && has(q)
        let extra = [r_i, d_i, t_i].map(has)

        let isPublicKey = !has(d) && !crt.contains(true) && other.isEmpty && !extra.contains(true)
        let isPrivateKeyTwoPrimes = has(d) && primes && other.isEmpty && !extra.contains(true)
        let isPrivateKeyMultiplePrimes = has(d) && primes && !other.isEmpty && !extra.contains(false)

        guard isPublicKey || isPrivateKeyTwoPrimes || isPrivateKeyMultiplePrimes else {
            throw CoseError.invalidKey("Invalid RSA key")
        }
        
        // Validate key type
        guard let ktyValue = transformedDict[KpKty()] as? CoseAttribute, ktyValue == KtyRSA() else {
            throw CoseError.invalidKey("Illegal key type in RSA COSE Key: \(String(describing: transformedDict[KpKty()]))")
        }
        
        // Transform optional parameters
        for (key, value) in optionalParams {
            let kp = try RSAKeyParam.fromId(for: key)
            if kp is KpKeyOps {
                transformedDict[kp] = try CoseKey.parseKeyOps(value, for: RSAKey.self)
                continue
            }
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
    
    /// The smallest RSA key size swift-crypto accepts for signing and
    /// encryption with raw key numbers.
    static let minimumKeyBits = 2048
    
    /// The bit length of the modulus `n`, ignoring leading zero bytes.
    var modulusBitLength: Int? {
        guard let n else { return nil }
        guard let first = n.firstIndex(where: { $0 != 0 }) else { return 0 }
        let significant = n.count - (first - n.startIndex)
        return (significant - 1) * 8 + (8 - n[first].leadingZeroBitCount)
    }
    
    /// Throws a clear error for a key swift-crypto would reject as too small.
    func requireSupportedSize() throws {
        guard let bits = modulusBitLength else {
            throw CoseError.invalidKey("RSA key has no modulus n")
        }
        guard bits >= RSAKey.minimumKeyBits else {
            throw CoseError.invalidKey("RSA keys must be at least \(RSAKey.minimumKeyBits) bits; this key's modulus is \(bits) bits")
        }
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
        guard keyBits >= RSAKey.minimumKeyBits else {
            throw CoseError.invalidKey("RSA keys must be at least \(RSAKey.minimumKeyBits) bits; \(keyBits) bits requested")
        }

        // Generate with swift-crypto, which guarantees a modulus of exactly
        // keyBits bits. CryptoSwift's generator multiplies two keyBits/2-bit
        // primes, so about half its "2048-bit" keys have a 2047-bit modulus,
        // which swift-crypto (4.5.2 and later) rejects as under 2048 bits.
        let generated: _RSA.Signing.PrivateKey
        do {
            generated = try _RSA.Signing.PrivateKey(keySize: .init(bitCount: keyBits))
        } catch {
            throw CoseError.invalidKey("RSA key generation failed: \(error)")
        }
        // Read the numbers back out of the PKCS #1 private key.
        let numbers = try pkcs1PrivateKeyNumbers(generated.derRepresentation)
        var coseKey: [AnyHashable: Any] = [
            RSAKpN(): numbers[0],
            RSAKpE(): numbers[1],
            RSAKpD(): numbers[2],
            RSAKpP(): numbers[3],
            RSAKpQ(): numbers[4],
            RSAKpDP(): numbers[5],
            RSAKpDQ(): numbers[6],
            RSAKpQInv(): numbers[7],
        ]
        for (key, value) in optionalParams {
            coseKey[key] = value
        }
        return try RSAKey.fromDictionary(coseKey)
    }
    
    /// Reads n, e, d, p, q, dp, dq and qInv from a two-prime PKCS #1
    /// `RSAPrivateKey` (RFC 8017, appendix A.1.2), as big-endian bytes
    /// without sign padding.
    static func pkcs1PrivateKeyNumbers(_ der: Data) throws -> [Data] {
        let bytes = [UInt8](der)
        var index = 0
        
        func fail() -> CoseError { CoseError.invalidKey("Malformed PKCS #1 RSA private key") }
        func readLength() throws -> Int {
            guard index < bytes.count else { throw fail() }
            let first = bytes[index]; index += 1
            if first < 0x80 { return Int(first) }
            let count = Int(first & 0x7F)
            guard count >= 1, count <= 4, index + count <= bytes.count else { throw fail() }
            var length = 0
            for _ in 0..<count { length = (length << 8) | Int(bytes[index]); index += 1 }
            return length
        }
        func readInteger() throws -> Data {
            guard index < bytes.count, bytes[index] == 0x02 else { throw fail() }
            index += 1
            let length = try readLength()
            guard length > 0, index + length <= bytes.count else { throw fail() }
            var value = bytes[index..<(index + length)]
            index += length
            while value.count > 1, value.first == 0 { value = value.dropFirst() }
            return Data(value)
        }
        
        guard bytes.first == 0x30 else { throw fail() }
        index = 1
        let length = try readLength()
        guard index + length == bytes.count else { throw fail() }
        guard try readInteger() == Data([0]) else {
            throw CoseError.invalidKey("Only two-prime RSA keys are supported")
        }
        return try (0..<8).map { _ in try readInteger() }
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
        
        // Every component must be a byte string. A value of another type
        // used to become nil here and then trap in init.
        func component(_ value: Any) throws -> Data? {
            guard let data = value as? Data else {
                throw CoseError.invalidKey("RSA key components must be byte strings")
            }
            return data.isEmpty ? nil : data
        }
        guard let otherPrimes = other as? [[String: Any]] else {
            throw CoseError.invalidKey("RSA key 'other' must be an array of maps")
        }
        return try RSAKey(
            n: try component(n),
            e: try component(e),
            d: try component(d),
            p: try component(p),
            q: try component(q),
            dp: try component(dp),
            dq: try component(dq),
            qInv: try component(qInv),
            other: otherPrimes,
            r_i: try component(r_i),
            d_i: try component(d_i),
            t_i: try component(t_i),
            optionalParams: optionalParams
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
