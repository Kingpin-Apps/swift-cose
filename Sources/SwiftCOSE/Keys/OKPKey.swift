import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import PotentCodables
import SwiftCurve448

public class OKPKey: CoseKey {
    public var optionalParams: [AnyHashable: Any]
    
    // MARK: - curve Property
    /// The mandatory `OKPKpCurve` attribute of the COSE OKP Key object.
    public var curve: CoseCurve {
        get {
            if store.contains(where: { $0.key == OKPKpCurve() as AnyHashable }) {
                return store[OKPKpCurve()] as! CoseCurve
            } else {
                fatalError("OKP COSE key must have the OKPKpCurve attribute")
            }
        }
        set {
            if newValue.keyType != .ktyOKP {
                fatalError("Invalid COSE curve \(newValue) for key type \(OKPKey.self)")
            }
            store[OKPKpCurve()] = newValue
        }
    }
    
    // MARK: - x Property
    /// The mandatory `OKPKpX` attribute of the COSE OKP Key object.
    public var x: Data? {
        get {
            return store[OKPKpX()] as? Data ?? nil
        }
        set {
            store[OKPKpX()] = newValue
        }
    }
    
    // MARK: - d Property
    /// The mandatory`OKPKpD` attribute of the COSE OKP Key object.
    public var d: Data? {
        get {
            return store[OKPKpD()] as? Data ?? nil
        }
        set {
            store[OKPKpD()] = newValue
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
                    fatalError("Invalid COSE key operation \(ops) for key type \(OKPKey.self)")
                }
            }
            _keyOps = newValue 
        }
    }
    
    // MARK: - Initialization Methods
    /// Create an COSE OKP key.
    /// - Parameters:
    ///   - curve: An OKP elliptic curve.
    ///   - x: Public value of the OKP key.
    ///   - d: Private value of the OKP key.
    ///   - optionalParams: A dictionary with optional key parameters.
    public init(curve: CoseCurve, x: Data? = nil, d: Data? = nil, optionalParams: [AnyHashable: Any] = [:]) throws {
        var transformedDict: [AnyHashable: Any] = [KpKty(): KtyOKP()]
        
        // Transform optional parameters
        for (key, value) in optionalParams {
            let kp = try OKPKeyParam.fromId(for: key)
            if let parser = kp.valueParser {
                if value is Array<AnyHashable> {
                    transformedDict[kp] = try (value as! Array<AnyHashable>).map { try parser($0) }
                } else {
                    transformedDict[kp] = try parser(value)
                }
            } else {
                transformedDict[kp] = value
            }
        }
        
        // Validate key type
        guard transformedDict[KpKty()] as! CoseAttribute == KtyOKP() else {
            throw CoseError.invalidKey("Illegal key type in OKP COSE Key: \(String(describing: transformedDict[KpKty()]))")
        }
        
        guard x != nil || d != nil else {
            throw CoseError.invalidKey("Public key cannot be empty")
        }
        
        self.optionalParams = optionalParams
        
        super.init(keyDict: transformedDict)
        
        self.curve = curve
        self.x = x
        self.d = d ?? Data()
    }
    
    // MARK: - Methods
    
    /// Returns an initialized COSE Key object of type OKPKey.
    /// - Parameter coseKey: Dictionary containing COSE Key parameters and there values.
    /// - Returns: An initialized OKPKey key
    public override static func fromDictionary(_ coseKey: [AnyHashable: Any]) throws -> OKPKey {
        let x = CoseKey.extractFromDict(coseKey, parameter: OKPKpX())
        let d = CoseKey.extractFromDict(coseKey, parameter: OKPKpD())
        let curveData = CoseKey.extractFromDict(coseKey, parameter: OKPKpCurve(), defaultValue: nil)
        let curve = try CoseCurve.fromId(for: curveData)
        
        var optionalParams: [AnyHashable : Any] = coseKey
        CoseKey.removeFromDict(&optionalParams, parameter: OKPKpX())
        CoseKey.removeFromDict(&optionalParams, parameter: OKPKpD())
        CoseKey.removeFromDict(&optionalParams, parameter: OKPKpCurve())
        
        return try OKPKey(
            curve: curve,
            x: x as? Data,
            d: d as? Data,
            optionalParams: optionalParams
        )
    }
    
    /// Returns an initialized COSE Key object of type `OKPKey`
    /// - Parameters:
    ///   - extKey: A private or public key.
    ///   - optionalParams: Optional additional parameters.
    /// - Throws: An error if the key type or curve is unsupported.
    /// - Returns: An initialized `OKPKey` object.
    public static func fromCryptographyKey(
        extKey: Any,
        optionalParams: [AnyHashable: Any] = [:]
    ) throws -> OKPKey {
        let curve = try curveFromCryptoKey(extKey)
        
        let (_, x, _, d) = try deriveNumbers(from: extKey)
        
        var coseKey: [AnyHashable : Any] = [
            OKPKpCurve(): curve.identifier ?? curve.fullname ?? curve as Any,
            OKPKpX(): x,
        ]
        
        if let d = d { coseKey[OKPKpD()] = d }
        
        // Merge optional params
        for (key, value) in optionalParams {
            coseKey[key] = value
        }

        // Initialize OKPKey from dictionary
        return try OKPKey.fromDictionary(coseKey)
    }
    
    /// Maps an external cryptographic key to a COSE curve type.
    /// - Parameter extKey: The external cryptographic key (public or private).
    /// - Returns: A `CoseCurve` representing the curve.
    /// - Throws: `CoseIllegalKeyType` if the key type is unsupported.
    public static func curveFromCryptoKey(_ extKey: Any) throws -> CoseCurve {
        if extKey is Curve25519.Signing.PrivateKey || extKey is Curve25519.Signing.PublicKey {
            return Ed25519Curve()
        }
        if extKey is Curve25519.KeyAgreement.PrivateKey || extKey is Curve25519.KeyAgreement.PublicKey {
            return X25519Curve()
        }
        if extKey is Curve448.Signing.PrivateKey || extKey is Curve448.Signing.PublicKey {
            return Ed448Curve()
        }
        if extKey is Curve448.KeyAgreement.PrivateKey || extKey is Curve448.KeyAgreement.PublicKey {
            return X448Curve()
        }
        
        throw CoseError.unsupportedCurve("Unsupported key type: \(type(of: extKey))")
    }
    
    /// Checks if the external cryptographic key type is supported.
    /// - Parameter extKey: The external cryptographic key (public or private).
    /// - Returns: `true` if the key type is supported; otherwise, `false`.
    public static func supportsCryptographyKeyType(_ extKey: Any) throws -> Bool {
        do {
            _ = try curveFromCryptoKey(extKey)
            return true
        } catch CoseError.unsupportedCurve {
            return false
        } catch {
            throw error
        }
    }

    /// Generate a random OKPKey COSE key object.
    ///
    /// - Parameters:
    ///  - curve: Specify an :class:`CoseCurve`.
    ///  - optionalParams: Optional key attributes for the :class:`OKPKey` object, e.g., `KpAlg` or `KpKid`.
    /// - Returns: An COSE `OKPKey` key.
    /// - Throws: `CoseError.unsupportedCurve` if the curve is not supported.
    public static func generateKey(curve: CoseCurve, optionalParams: [AnyHashable: AnyValue] = [:]) throws -> OKPKey {
        if curve.keyType != .ktyOKP {
            throw CoseError.invalidKey("Invalid curve type \(curve) for key type \(OKPKey.self)")
        }
        
        switch curve.curveType {
            case .ED25519:
                let privateKey: Curve25519.Signing.PrivateKey = try generateSigningPrivateKey(
                    curve: curve.curveType!
                )
                return try OKPKey.fromCryptographyKey(extKey: privateKey, optionalParams: optionalParams)
            case .ED448:
                let privateKey: Curve448.Signing.PrivateKey = try generateSigningPrivateKey(curve: curve.curveType!)
                return try OKPKey.fromCryptographyKey(extKey: privateKey, optionalParams: optionalParams)
            case .X25519:
                let privateKey: Curve25519.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: curve.curveType!)
                return try OKPKey.fromCryptographyKey(extKey: privateKey, optionalParams: optionalParams)
            case .X448:
                let privateKey: Curve448.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: curve.curveType!)
                return try OKPKey.fromCryptographyKey(extKey: privateKey, optionalParams: optionalParams)
            default:
                throw CoseError.invalidCurve("Invalid curve type")
        }
    }
    
    // Function to delete a key
    func delete(key: AnyHashable) throws {
        if let key = key as? OKPKeyParam {
            return try delete(key: key.identifier)
        } else {
            let transformedKey = try OKPKeyParam.fromId(for: key)

            if transformedKey != KpKty() && transformedKey != OKPKpCurve() {
                if transformedKey == OKPKpD() && store[OKPKpX()] == nil {
                    return  // Do nothing
                } else if transformedKey == OKPKpX() && store[OKPKpD()] == nil {
                    return  // Do nothing
                } else {
                    store.removeValue(forKey: transformedKey as AnyHashable)
                    return
                }
            }
        }

        throw CoseError
            .invalidKey(
                "Deleting \(key) attribute would lead to an invalid COSE OKP Key"
            )
    }

    // Custom description for the object
    public override var description: String {
        var keyRepresentation = keyRepr()
        
        if let okpD = keyRepresentation[OKPKpD()] as? Data, !okpD.isEmpty {
            keyRepresentation[OKPKpD()] = truncate(okpD.base64EncodedString())
        }
        if let okpX = keyRepresentation[OKPKpX()] as? Data, !okpX.isEmpty {
            keyRepresentation[OKPKpX()] = truncate(okpX.base64EncodedString())
        }

        return "<COSE_Key(OKPKey): \(keyRepresentation)>"
    }
}
