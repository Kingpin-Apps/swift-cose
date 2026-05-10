import Foundation
import PotentCodables
import CryptoKit
import P256K

public class EC2Key: CoseKey {
    public var optionalParams: [AnyHashable: Any]
    
    // MARK: - curve Property
    /// The mandatory curve attribute for the EC2Key.
    public var curve: CoseCurve {
        get {
            if store.contains(where: { $0.key == EC2KpCurve() as AnyHashable }) {
                return store[EC2KpCurve()] as! CoseCurve
            } else {
                fatalError("EC2 COSE key must have the EC2KpCurve attribute")
            }
        }
        set {
            if newValue.keyType != .ktyEC2 {
                fatalError("Invalid COSE curve \(newValue) for key type \(EC2Key.self)")
            }
            store[EC2KpCurve()] = newValue
        }
    }
    
    // MARK: - x Property
    /// The mandatory `EC2KpX` attribute of the COSE EC2 Key object.
    var x: Data? {
        get {
            return store[EC2KpX()] as? Data ?? nil
        }
        set {
            store[EC2KpX()] = newValue
        }
    }
    
    // MARK: - y Property
    /// The mandatory`EC2KpY` attribute of the COSE EC2 Key object.
    var y: Data? {
        get {
            return store[EC2KpY()] as? Data ?? nil
        }
        set {
            store[EC2KpY()] = newValue
        }
    }
    
    // MARK: - d Property
    /// The mandatory`EC2KpD` attribute of the COSE EC2 Key object.
    var d: Data? {
        get {
            return store[EC2KpD()] as? Data ?? nil
        }
        set {
            store[EC2KpD()] = newValue
        }
    }
    
    // MARK: - Key Operations
    private var _keyOps: [KeyOps] = []
    public override var keyOps: [KeyOps] {
        get {
            return _keyOps as [KeyOps]
        }
        set {
            for ops in newValue {
                if !supportedOps.contains(where: { $0 == type(of: ops) }) {
                    fatalError("Invalid COSE key operation \(ops) for key type \(EC2Key.self)")
                }
            }
            _keyOps = newValue 
        }
    }
    
    // MARK: - Supported Key Operations
    private let supportedOps: [KeyOps.Type] = [
        SignOp.self,
        VerifyOp.self,
        DeriveKeyOp.self,
        DeriveBitsOp.self
    ]
    
    // MARK: - Helpers
    
    public static func supportsCryptographyKeyType(_ key: Any) -> Bool {
        let supportedKeyTypes: [Any] = [
            P256K.KeyAgreement.PrivateKey.self,
            P256K.KeyAgreement.PublicKey.self,
            P256K.Signing.PrivateKey.self,
            P256K.Signing.PublicKey.self,
            P256.Signing.PrivateKey.self,
            P256.Signing.PublicKey.self,
            P256.KeyAgreement.PrivateKey.self,
            P256.KeyAgreement.PublicKey.self,
            P384.Signing.PrivateKey.self,
            P384.Signing.PublicKey.self,
            P384.KeyAgreement.PrivateKey.self,
            P384.KeyAgreement.PublicKey.self,
            P521.Signing.PrivateKey.self,
            P521.Signing.PublicKey.self,
            P521.KeyAgreement.PrivateKey.self,
            P521.KeyAgreement.PublicKey.self
        ]
        
        return supportedKeyTypes.contains(where: { $0 as? any Any.Type == type(of: key) })
    }
    
    // MARK: - Initializtion
    /// Initialize a COSE key from its components
    ///
    ///  Not passing a `y` component is accepted; in this case, one (of the two)
    ///  valid `y` will be found for the `x`. This is good enough for everything
    ///  that only operates on the `x` of any derived outputs (in "compact"
    ///  mode), as per RFC 6090 Section 4.2.
    ///
    /// - Parameters:
    ///   - curve: The curve of the key.
    ///   - x: The x component of the key.
    ///   - y: The y component of the key.
    ///   - d: The private key of the key.
    ///   - optionalParams: Additional parameters for the key.
    init(curve: CoseCurve, x: Data? = nil, y: Data? = nil, d: Data? = nil, optionalParams: [AnyHashable: Any] = [:]) throws {
        var transformedDict: [AnyHashable: Any] = [KpKty(): KtyEC2()]
        
        // Transform optional parameters
        for (key, value) in optionalParams {
            let kp = try EC2KeyParam.fromId(for: key)
            if let parser = kp.valueParser {
                transformedDict[kp] = try parser(value)
            } else {
                transformedDict[kp] = value
            }
        }
        
        // Validate key type
        guard transformedDict[KpKty()] as! CoseAttribute == KtyEC2() else {
            throw CoseError.invalidKey("Illegal key type in EC2 COSE Key: \(String(describing: transformedDict[KpKty()]))")
        }
        
        guard x != nil || y != nil || d != nil else {
            throw CoseError.invalidKey("Either the public values or the private value must be specified")
        }
        
        self.optionalParams = transformedDict
        
        super.init(keyDict: transformedDict)
        
        self.curve = curve
        
        if d != nil {
            // Derive public key (x, y) from private key `d`
            let (publicKeyX, publicKeyY) = try deriveKeyAgreementPublicNumbers(from: d!, curve: curve.curveType!)
            
            if let x = x, publicKeyX != x {
                throw CoseError.invalidKey("Public X does not match derived X")
            }
            if let y = y, publicKeyY != y {
                throw CoseError.invalidKey("Public Y does not match derived Y")
            }
        }
        
        if x != nil && y == nil {
            // Attempt to derive Y from X
            let publicKeyData = Data(
                [0x03]
            ) + x! // don't care which of the two possible Y values we get
            let (_, publicKeyY) = try deriveKeyAgreementPublicNumbersCompact(
                from: publicKeyData,
                curve: curve.curveType!
            )
            self.y = publicKeyY!
        }
        
        self.x = x!
        self.y = y!
        self.d = d!
    }

    // MARK: - Methods
    
    /// Returns an initialized COSE Key object of type EC2Key.
    /// - Parameter coseKey: Dict containing COSE Key parameters and their values.
    /// - Returns: An initialized EC2Key key
    public override class func fromDictionary(_ coseKey: [AnyHashable: Any]) throws -> EC2Key {
        let x = CoseKey.extractFromDict(coseKey, parameter: EC2KpX())
        let y = CoseKey.extractFromDict(coseKey, parameter: EC2KpY())
        let d = CoseKey.extractFromDict(coseKey, parameter: EC2KpD())
        let curveData = CoseKey.extractFromDict(coseKey, parameter: EC2KpCurve(), defaultValue: nil)
        let curve = try CoseCurve.fromId(for: curveData)
        
        var optionalParams: [AnyHashable : Any] = coseKey
        CoseKey.removeFromDict(&optionalParams, parameter: EC2KpX())
        CoseKey.removeFromDict(&optionalParams, parameter: EC2KpY())
        CoseKey.removeFromDict(&optionalParams, parameter: EC2KpD())
        CoseKey.removeFromDict(&optionalParams, parameter: EC2KpCurve())
        
        return try EC2Key(
            curve: curve,
            x: x as? Data,
            y: y as? Data,
            d: d as? Data,
            optionalParams: optionalParams
        )
    }
    
    /// Generate a random EC2Key COSE key object.
    /// - Parameters:
    ///   - curve: Specify an :class:`CoseCurve`.
    ///   - optionalParams: Optional key attributes for the :class:`EC2Key` object, e.g., `KpAlg` or `KpKid`.
    /// - Returns: An COSE `EC2Key` key.
    static func generateKey(curve: CoseCurve, optionalParams: [AnyHashable: AnyValue] = [:]) throws -> EC2Key {
        if curve.keyType != .ktyEC2 {
            throw CoseError.invalidKey("Invalid curve type \(curve) for key type \(EC2Key.self)")
        }
        
        switch curve.curveType {
            case .SECP256K1:
                let privateKey: P256K.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: curve.curveType!)
                return try EC2Key.fromCryptographyKey(extKey: privateKey, optionalParams: optionalParams)
            case .SECP256R1:
                let privateKey: P256.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: curve.curveType!)
                return try EC2Key.fromCryptographyKey(extKey: privateKey, optionalParams: optionalParams)
            case .SECP384R1:
                let privateKey: P384.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: curve.curveType!)
                return try EC2Key.fromCryptographyKey(extKey: privateKey, optionalParams: optionalParams)
            case .SECP521R1:
                let privateKey:P521.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: curve.curveType!)
                return try EC2Key.fromCryptographyKey(extKey: privateKey, optionalParams: optionalParams)
            default:
                throw CoseError.invalidCurve("Invalid curve type")
        }
    }
    
    /// Returns an initialized COSE Key object of type `EC2Key`
    /// - Parameters:
    ///   - extKey: A private or public key.
    ///   - optionalParams: Optional additional parameters.
    /// - Throws: An error if the key type or curve is unsupported.
    /// - Returns: An initialized `EC2Key` object.
    public static func fromCryptographyKey(
        extKey: Any,
        optionalParams: [AnyHashable: Any] = [:]
    ) throws -> EC2Key {
        guard EC2Key.supportsCryptographyKeyType(extKey) else {
            throw CoseError.invalidKey("Unsupported key type: \(type(of: extKey))")
        }
        
        let (curveType, x, y, d) = try deriveNumbers(from: extKey)
        
        var curves: [CurveType: CoseCurve] = [:]
        for identifier in CoseCurveIdentifier.allCases {
            let coseCurve = try CoseCurve.fromId(for: identifier)
            if coseCurve.keyType == .ktyEC2 {
                curves[coseCurve.curveType!] = coseCurve
            }
        }
        
        if !curves.keys.contains(curveType) {
            throw CoseError.invalidCurve("Unsupported EC Curve: \(type(of: curveType))")
        }
        
        var coseKey: [AnyHashable: Any] = [:]

        coseKey[EC2KpCurve()] = curves[curveType]!.identifier
        coseKey[EC2KpX()] = x
        
        if let y = y { coseKey[EC2KpY()] = y }
        if let d = d { coseKey[EC2KpD()] = d }

        // Merge optional params
        for (key, value) in optionalParams {
            coseKey[key] = value
        }

        // Initialize EC2Key from dictionary
        return try EC2Key.fromDictionary(coseKey)
    }
    

    // Function to delete a key
    func delete(key: AnyHashable) throws {
        if let key = key as? EC2KeyParam {
            return try delete(key: key.identifier)
        } else {
            let transformedKey = try EC2KeyParam.fromId(for: key)

            if transformedKey != KpKty() && transformedKey != EC2KpCurve() {
                if transformedKey == EC2KpD() && (store[EC2KpY()] == nil || store[EC2KpX()] == nil) {
                    return  // Do nothing
                } else if transformedKey == EC2KpX() && store[EC2KpD()] == nil {
                    return  // Do nothing
                } else if (transformedKey == EC2KpX() || transformedKey == EC2KpY()) && store[EC2KpD()] != nil {
                    store.removeValue(forKey: EC2KpX())
                    store.removeValue(forKey: EC2KpY())
                    return
                } else {
                    store.removeValue(forKey: transformedKey as AnyHashable)
                    return
                }
            }
        }

        throw CoseError
            .invalidKey(
                "Deleting \(key) attribute would lead to an invalid COSE EC2 Key"
            )
    }

    // Custom description for the object
    public override var description: String {
        var keyRepresentation = keyRepr()
        
        if let ec2D = keyRepresentation[EC2KpD()] as? Data, !ec2D.isEmpty {
            keyRepresentation[EC2KpD()] = truncate(ec2D.base64EncodedString())
        }
        if let ec2X = keyRepresentation[EC2KpX()] as? Data, !ec2X.isEmpty {
            keyRepresentation[EC2KpX()] = truncate(ec2X.base64EncodedString())
        }
        if let ec2Y = keyRepresentation[EC2KpY()] as? Data, !ec2Y.isEmpty {
            keyRepresentation[EC2KpY()] = truncate(ec2Y.base64EncodedString())
        }

        return "<COSE_Key(EC2Key): \(keyRepresentation)>"
    }
}
