import Foundation

// MARK: - Common Key Parameters

/// Enumerates the common key parameters
public enum KeyParamIdentifier: Int, CaseIterable, Sendable {
    case kty = 1
    case kid = 2
    case alg = 3
    case keyOps = 4
    case baseIV = 5
    
    /// Returns the appropriate `CoseKeyParam` subclass for the given full name.
    /// - Parameter fullName: The string fullname of the key parameter.
    /// - Returns: An instance of the corresponding `CoseKeyParam` subclass if found, otherwise nil.
    public static func fromFullName(_ fullName: String) -> KeyParamIdentifier? {
        switch fullName.uppercased() {
            case "KTY": return .kty
            case "KID": return .kid
            case "ALG": return .alg
            case "KEY_OPS": return .keyOps
            case "BASE_IV": return .baseIV
            default: return nil
        }
    }
}


public class KeyParam: CoseAttribute {
    public init(
        identifier: KeyParamIdentifier,
        fullname: String,
        valueParser: ((Any) throws -> Any)? = nil
    ) {
        super.init(
            identifier: identifier.rawValue,
            fullname: fullname,
            valueParser: valueParser
        )
    }
    public init(
        rawValue: Int,
        fullname: String,
        valueParser: ((Any) throws -> Any)? = nil
    ) {
        super.init(
            identifier: rawValue,
            fullname: fullname,
            valueParser: valueParser
        )
    }
    
    /// Returns the specific KeyParam subclass for a given identifier.
    /// - Parameter identifier: The identifier (Int or KeyParamIdentifier).
    /// - Returns: An instance of the corresponding KeyParam subclass.
    public class func fromId(for identifier: Any) throws -> KeyParam {
        switch identifier {
            case let id as any BinaryInteger:
                guard let intId = intExactly(id), let keyType = KeyParamIdentifier(rawValue: intId) else {
                    throw CoseError.invalidKeyType("Unknown KeyParam identifier: \(id)")
                }
                return getInstance(for: keyType)
                    
            case let name as String:
                // If the identifier is a String, attempt to match it to a KeyParamIdentifier
                guard let type = KeyParamIdentifier.fromFullName(name) else {
                    throw CoseError.invalidKeyType("Unknown type fullname")
                }
                return getInstance(for: type)
                    
            case let type as KeyParamIdentifier:
                return getInstance(for: type)
            default:
                throw CoseError.invalidKeyType("Unsupported identifier type: \(type(of: identifier))")
        }
    }
    
    /// Maps the `KeyParamIdentifier` to its corresponding class type.
    /// - Parameter identifier: The identifier to map.
    /// - Returns: An instance of the corresponding subclass.
    public static func getInstance(for identifier: KeyParamIdentifier) -> KeyParam {
        switch identifier {
            case .kty: return KpKty()
            case .kid: return KpKid()
            case .alg: return KpAlg()
            case .keyOps: return KpKeyOps()
            case .baseIV: return KpBaseIV()
        }
    }
}

// Subclasses for common key parameters
public class KpKty: KeyParam {
    public init() {
        super.init(
            identifier: .kty,
            fullname: "KTY",
            valueParser: KTY.fromId
        )
    }
}

public class KpKid: KeyParam {
    public init() {
        super.init(
            identifier: .kid,
            fullname: "KID"
        )
    }
}

public class KpAlg: KeyParam {
    public init() {
        super.init(
            identifier: .alg,
            fullname: "ALG",
            valueParser: CoseAlgorithm.fromId
        )
    }
}

public class KpKeyOps: KeyParam {
    public init() {
        super.init(
            identifier: .keyOps,
            fullname: "KEY_OPS",
            valueParser: KeyOps.fromId
        )
    }
}

public class KpBaseIV: KeyParam {
    public init() {
        super.init(
            identifier: .baseIV,
            fullname: "BASE_IV"
        )
    }
}

//public class CoseKeyParam: CoseAttribute {}

// MARK: - EC2 Key Parameters

/// Enumerates the EC2 key parameters
public enum EC2KeyParamIdentifier: Int, CaseIterable, Sendable {
    case kty = 1
    case kid = 2
    case alg = 3
    case keyOps = 4
    case baseIV = 5
    case curve = -1
    case x = -2
    case y = -3
    case d = -4
    
    /// Returns the appropriate `EC2KeyParamIdentifier` for the given fullname.
    /// - Parameter fullname: The string fullname of the EC2 key parameter.
    /// - Returns: The corresponding `EC2KeyParamIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullname: String) -> EC2KeyParamIdentifier? {
        switch fullname.uppercased() {
            case "KTY": return .kty
            case "KID": return .kid
            case "ALG": return .alg
            case "KEY_OPS": return .keyOps
            case "BASE_IV": return .baseIV
            case "CURVE": return .curve
            case "X": return .x
            case "Y": return .y
            case "D": return .d
            default: return nil
        }
    }
}
    
// Base class for EC2 key parameters
public class EC2KeyParam: KeyParam {

    public init(
        identifier: EC2KeyParamIdentifier,
        fullname: String,
        valueParser: ((Any) throws -> Any)? = nil
    ) {
        super.init(
            rawValue: identifier.rawValue,
            fullname: fullname,
            valueParser: valueParser
        )
    }
    
    /// Returns the specific EC2KeyParam subclass for a given identifier.
    /// - Parameter identifier: The identifier (Int or EC2KeyParamIdentifier).
    /// - Returns: An instance of the corresponding EC2KeyParam subclass.
    public override class func fromId(for identifier: Any) throws -> KeyParam {
        switch identifier {
            case let id as Int:
                guard let keyType = EC2KeyParamIdentifier(rawValue: id) else {
                    throw CoseError.invalidKeyType("Unknown EC2KeyParam identifier")
                }
                return getInstance(for: keyType)
                    
            case let name as String:
                // If the identifier is a String, attempt to match it to a EC2KeyParamIdentifier
                guard let type = EC2KeyParamIdentifier.fromFullName(name) else {
                    throw CoseError.invalidKeyType("Unknown type fullname")
                }
                return getInstance(for: type)
                    
            case let type as EC2KeyParamIdentifier:
                return getInstance(for: type)
            default:
                throw CoseError.invalidKeyType("Unsupported identifier type: \(type(of: identifier))")
        }
    }
    
    /// Maps the `EC2KeyParamIdentifier` to its corresponding class type.
    /// - Parameter identifier: The identifier to map.
    /// - Returns: An instance of the corresponding subclass.
    public static func getInstance(for identifier: EC2KeyParamIdentifier) -> KeyParam {
        switch identifier {
            case .kty: return KpKty()
            case .kid: return KpKid()
            case .alg: return KpAlg()
            case .keyOps: return KpKeyOps()
            case .baseIV: return KpBaseIV()
            case .curve: return EC2KpCurve()
            case .x: return EC2KpX()
            case .y: return EC2KpY()
            case .d: return EC2KpD()
        }
    }
}

public class EC2KpCurve: EC2KeyParam {
    public init() {
        super.init(
            identifier: .curve,
            fullname: "CURVE",
            valueParser: CoseCurve.fromId
        )
    }
}

public class EC2KpX: EC2KeyParam {
    public init() {
        super.init(
            identifier: .x,
            fullname: "X"
        )
    }
}

public class EC2KpY: EC2KeyParam {
    public init() {
        super.init(
            identifier: .y,
            fullname: "Y"
        )
    }
}

public class EC2KpD: EC2KeyParam {
    public init() {
        super.init(
            identifier: .d,
            fullname: "D"
        )
    }
}

// MARK: - OKP Key Parameters

/// Enumerates the EC2 key parameters
public enum OKPKeyParamIdentifier: Int, CaseIterable, Sendable {
    case kty = 1
    case kid = 2
    case alg = 3
    case keyOps = 4
    case baseIV = 5
    case curve = -1
    case x = -2
    case d = -4
    
    /// Returns the appropriate `OKPKeyParamIdentifier` for the given fullname.
    /// - Parameter fullname: The string fullname of the OKP key parameter.
    /// - Returns: The corresponding `OKPKeyParamIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullname: String) -> OKPKeyParamIdentifier? {
        switch fullname.uppercased() {
            case "KTY": return .kty
            case "KID": return .kid
            case "ALG": return .alg
            case "KEY_OPS": return .keyOps
            case "BASE_IV": return .baseIV
            case "CURVE": return .curve
            case "X": return .x
            case "D": return .d
            default: return nil
        }
    }
}

// Base class for OKP key parameters
public class OKPKeyParam: KeyParam {
    public init(
        identifier: OKPKeyParamIdentifier,
        fullname: String,
        valueParser: ((Any) throws -> Any)? = nil
    ) {
        super.init(
            rawValue: identifier.rawValue,
            fullname: fullname,
            valueParser: valueParser
        )
    }
    
    /// Returns the specific OKPKeyParam subclass for a given identifier.
    public override class func fromId(for identifier: Any) throws -> KeyParam {
        switch identifier {
            case let id as Int:
                guard let keyType = OKPKeyParamIdentifier(rawValue: id) else {
                    throw CoseError.invalidKeyType("Unknown OKPKeyParam identifier")
                }
                return getInstance(for: keyType)

            case let name as String:
                guard let type = OKPKeyParamIdentifier.fromFullName(name) else {
                    throw CoseError.invalidKeyType("Unknown type fullname")
                }
                return getInstance(for: type)

            case let type as OKPKeyParamIdentifier:
                return getInstance(for: type)
                    
            case let keyParam as KeyParam:
                // If the identifier is already a KeyParam get the instance directly
                return keyParam
            default:
                throw CoseError.invalidKeyType("Unsupported identifier type: \(type(of: identifier))")
        }
    }

    /// Maps the OKPKeyParamIdentifier to its corresponding class type.
    public static func getInstance(for identifier: OKPKeyParamIdentifier) -> KeyParam {
        switch identifier {
            case .kty: return KpKty()
            case .kid: return KpKid()
            case .alg: return KpAlg()
            case .keyOps: return KpKeyOps()
            case .baseIV: return KpBaseIV()
            case .curve: return OKPKpCurve()
            case .x: return OKPKpX()
            case .d: return OKPKpD()
        }
    }
}

// Subclasses for OKP key parameters
public class OKPKpCurve: OKPKeyParam {
    public init() {
        super.init(
            identifier: .curve,
            fullname: "CURVE",
            valueParser: CoseCurve.fromId
        )
    }
}

public class OKPKpX: OKPKeyParam {
    public init() {
        super.init(
            identifier: .x,
            fullname: "X"
        )
    }
}

public class OKPKpD: OKPKeyParam {
    public init() {
        super.init(
            identifier: .d,
            fullname: "D"
        )
    }
}

// MARK: - RSA Key Parameters

/// Enumerates the RSA key parameters
public enum RSAKeyParamIdentifier: Int, CaseIterable, Sendable {
    case kty = 1
    case kid = 2
    case alg = 3
    case keyOps = 4
    case baseIV = 5
    case n = -1
    case e = -2
    case d = -3
    case p = -4
    case q = -5
    case dp = -6
    case dq = -7
    case qInv = -8
    case other = -9
    case r_i = -10
    case d_i = -11
    case t_i = -12
    
    /// Returns the appropriate `RSAKeyParamIdentifier` for the given fullname.
    /// - Parameter fullname: The string fullname of the RSA key parameter.
    /// - Returns: The corresponding `RSAKeyParamIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullname: String) -> RSAKeyParamIdentifier? {
        switch fullname.uppercased() {
            case "KTY": return .kty
            case "KID": return .kid
            case "ALG": return .alg
            case "KEY_OPS": return .keyOps
            case "BASE_IV": return .baseIV
            case "N": return .n
            case "E": return .e
            case "D": return .d
            case "P": return .p
            case "Q": return .q
            case "DP": return .dp
            case "DQ": return .dq
            case "QINV": return .qInv
            case "OTHER": return .other
            case "R_I": return .r_i
            case "D_I": return .d_i
            case "T_I": return .t_i
            default: return nil
        }
    }
}

// Base class for RSA key parameters
public class RSAKeyParam: KeyParam {
    public init(
        identifier: RSAKeyParamIdentifier,
        fullname: String
    ) {
        super.init(rawValue: identifier.rawValue, fullname: fullname)
    }
    
    /// Returns the specific RSAKeyParam subclass for a given identifier.
    public override class func fromId(for identifier: Any) throws -> KeyParam {
        switch identifier {
        case let id as Int:
            guard let keyType = RSAKeyParamIdentifier(rawValue: id) else {
                throw CoseError.invalidKeyType("Unknown RSAKeyParam identifier")
            }
            return getInstance(for: keyType)

        case let name as String:
            guard let type = RSAKeyParamIdentifier.fromFullName(name) else {
                throw CoseError.invalidKeyType("Unknown type fullname")
            }
            return getInstance(for: type)

        case let type as RSAKeyParamIdentifier:
            return getInstance(for: type)
        default:
            throw CoseError.invalidKeyType("Unsupported identifier type: \(type(of: identifier))")
        }
    }

    /// Maps the RSAKeyParamIdentifier to its corresponding class type.
    public static func getInstance(for identifier: RSAKeyParamIdentifier) -> KeyParam {
        switch identifier {
            case .kty: return KpKty()
            case .kid: return KpKid()
            case .alg: return KpAlg()
            case .keyOps: return KpKeyOps()
            case .baseIV: return KpBaseIV()
            case .n: return RSAKpN()
            case .e: return RSAKpE()
            case .d: return RSAKpD()
            case .p: return RSAKpP()
            case .q: return RSAKpQ()
            case .dp: return RSAKpDP()
            case .dq: return RSAKpDQ()
            case .qInv: return RSAKpQInv()
            case .other: return RSAKpOther()
            case .r_i: return RSAKpRi()
            case .d_i: return RSAKpDi()
            case .t_i: return RSAKpTi()
        }
    }
}

// Subclasses for RSA key parameters
public class RSAKpN: RSAKeyParam {
    public init() {
        super.init(
            identifier: .n,
            fullname: "N"
        )
    }
}

public class RSAKpE: RSAKeyParam {
    public init() {
        super.init(
            identifier: .e,
            fullname: "E"
        )
    }
}

public class RSAKpD: RSAKeyParam {
    public init() {
        super.init(
            identifier: .d,
            fullname: "D"
        )
    }
}

public class RSAKpP: RSAKeyParam {
    public init() {
        super.init(
            identifier: .p,
            fullname: "P"
        )
    }
}

public class RSAKpQ: RSAKeyParam {
    public init() {
        super.init(
            identifier: .q,
            fullname: "Q"
        )
    }
}

public class RSAKpDP: RSAKeyParam {
    public init() {
        super.init(
            identifier: .dp,
            fullname: "DP"
        )
    }
}

public class RSAKpDQ: RSAKeyParam {
    public init() {
        super.init(
            identifier: .dq,
            fullname: "DQ"
        )
    }
}

public class RSAKpQInv: RSAKeyParam {
    public init() {
        super.init(
            identifier: .qInv,
            fullname: "QINV"
        )
    }
}

public class RSAKpOther: RSAKeyParam {
    public init() {
        super.init(
            identifier: .other,
            fullname: "OTHER"
        )
    }
}

public class RSAKpRi: RSAKeyParam {
    public init() {
        super.init(
            identifier: .r_i,
            fullname: "R_I"
        )
    }
}

public class RSAKpDi: RSAKeyParam {
    public init() {
        super.init(
            identifier: .d_i,
            fullname: "D_I"
        )
    }
}

public class RSAKpTi: RSAKeyParam {
    public init() {
        super.init(
            identifier: .t_i,
            fullname: "T_I"
        )
    }
}


// MARK: - Symmetric Key Parameters

/// Enumerates the Symmetric key parameters
public enum SymmetricKeyParamIdentifier: Int, CaseIterable, Sendable {
    case kty = 1
    case kid = 2
    case alg = 3
    case keyOps = 4
    case baseIV = 5
    case k = -1
    
    public static func fromSymmetricKeyParam(_ keyParam: KeyParam) throws -> SymmetricKeyParamIdentifier {
        if let fullname = keyParam.fullname {
            guard let id = SymmetricKeyParamIdentifier.fromFullName(fullname) else {
                throw CoseError.invalidAlgorithm("Unknown fullname \(fullname)")
            }
            return id
        } else if let identifier = keyParam.identifier {
            guard let id = SymmetricKeyParamIdentifier(rawValue: identifier) else {
                throw CoseError.invalidAlgorithm("Unknown identifier \(identifier)")
            }
            return id
        } else {
            throw CoseError
                .invalidKeyType("Key Parameters not properly initialized")
        }
    }
    
    /// Returns the appropriate `SymmetricKeyParamIdentifier` for the given fullname.
    /// - Parameter fullname: The string fullname of the RSA key parameter.
    /// - Returns: The corresponding `SymmetricKeyParamIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullname: String) -> SymmetricKeyParamIdentifier? {
        switch fullname.uppercased() {
            case "KTY": return .kty
            case "KID": return .kid
            case "ALG": return .alg
            case "KEY_OPS": return .keyOps
            case "BASE_IV": return .baseIV
            case "K": return .k
            default: return nil
        }
    }
}

// Base class for Symmetric key parameters
public class SymmetricKeyParam: KeyParam {
    public init(
        identifier: SymmetricKeyParamIdentifier,
        fullname: String
    ) {
        super.init(rawValue: identifier.rawValue, fullname: fullname)
    }
    
    /// Returns the specific SymmetricKeyParam subclass for a given identifier.
    public override class func fromId(for identifier: Any) throws -> KeyParam {
        switch identifier {
            case let id as Int:
                guard let keyType = SymmetricKeyParamIdentifier(rawValue: id) else {
                    throw CoseError.invalidKeyType("Unknown SymmetricKeyParam identifier")
                }
                return getInstance(for: keyType)

            case let name as String:
                guard let type = SymmetricKeyParamIdentifier.fromFullName(name) else {
                    throw CoseError.invalidKeyType("Unknown type fullname")
                }
                return getInstance(for: type)

            case let type as SymmetricKeyParamIdentifier:
                return getInstance(for: type)

            case let type as KeyParam:
                let keyType = try SymmetricKeyParamIdentifier.fromSymmetricKeyParam(type)
                return getInstance(for: keyType)
            default:
                throw CoseError.invalidKeyType("Unsupported identifier type: \(type(of: identifier))")
        }
    }

    /// Maps the SymmetricKeyParamIdentifier to its corresponding class type.
    public static func getInstance(for identifier: SymmetricKeyParamIdentifier) -> KeyParam {
        switch identifier {
            case .kty: return KpKty()
            case .kid: return KpKid()
            case .alg: return KpAlg()
            case .keyOps: return KpKeyOps()
            case .baseIV: return KpBaseIV()
            case .k: return SymKpK()
        }
    }
}

// Subclasses for Symmetric key parameters
public class SymKpK: SymmetricKeyParam {
    public init() {
        super.init(
            identifier: .k,
            fullname: "K"
        )
    }
}
