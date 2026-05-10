import Foundation
import UncommonCrypto
import CryptoKit
import P256K
import SwiftCurve448

public enum CurveType: Int, CaseIterable, Sendable {
    case SECP256K1
    case SECP256R1
    case SECP384R1
    case SECP521R1
    case ED25519
    case ED448
    case X25519
    case X448
}


public enum KeyType: Int, CaseIterable, Sendable {
    case ktyEC2
    case ktyOKP
    case none
}


public enum CoseCurveIdentifier: Int, CaseIterable, Sendable {
    case reserved = 0
    case p256 = 1
    case p384 = 2
    case p521 = 3
    case x25519 = 4
    case x448 = 5
    case ed25519 = 6
    case ed448 = 7
    case secp256k1 = 8
    
    /// Returns the appropriate `CoseCurveIdentifier` for the given fullname.
    /// - Parameter fullname: The string fullname of the curve.
    /// - Returns: The corresponding `CoseCurveIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullname: String) -> CoseCurveIdentifier? {
        switch fullname.uppercased() {
            case "RESERVED":
                return .reserved
            case "P_256":
                return .p256
            case "P_384":
                return .p384
            case "P_521":
                return .p521
            case "X25519":
                return .x25519
            case "X448":
                return .x448
            case "ED25519":
                return .ed25519
            case "ED448":
                return .ed448
            case "SECP256K1":
                return .secp256k1
            default:
                return nil
        }
    }
}

/// Base class for all COSE curves
public class CoseCurve: CoseAttribute {
    public var curveType: CurveType?
    public var keyType: KeyType?
    public var size: Int
    
    public init(
        identifier: CoseCurveIdentifier,
        fullname: String,
        size: Int,
        curveType: CurveType? = nil,
        keyType: KeyType? = nil
    ) {
        self.curveType = curveType
        self.keyType = keyType
        self.size = size
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
    
    /// Returns the appropriate `CoseCurve` instance for the given identifier or name.
    /// - Parameter attribute: The identifier or name of the curve.
    /// - Returns: A specific `CoseCurve` instance.
    public static func fromId(for attribute: Any) throws -> CoseCurve {
        switch attribute {
            case let id as any BinaryInteger:
                // If the identifier is an Int, convert it to CoseCurveIdentifier
                guard let curve = CoseCurveIdentifier(rawValue: Int(id)) else {
                    throw CoseError.invalidCurve("Unknown curve identifier")
                }
                return getInstance(for: curve)
                
            case let name as String:
                // If the identifier is a String, attempt to match it to a CoseCurveIdentifier
                guard let curve = CoseCurveIdentifier.fromFullName(name) else {
                    throw CoseError.invalidCurve("Unknown curve fullname")
                }
                return getInstance(for: curve)
                
            case let curve as CoseCurve:
                // If the identifier is already a CoseCurve get the instance directly
                return curve
                
            case let curve as CoseCurveIdentifier:
                // If the identifier is already a CoseCurveIdentifier, get the instance directly
                return getInstance(for: curve)
                
            default:
                throw CoseError.invalidCurve("Unsupported identifier type. Must be Int, String, or CoseCurveIdentifier")
        }
    }

    /// Returns the appropriate `CoseCurve` instance for the given identifier.
    /// - Parameter identifier: The `CoseCurveIdentifier` to create an instance for.
    /// - Returns: A specific `CoseCurve` instance.
    public static func getInstance(for identifier: CoseCurveIdentifier) -> CoseCurve {
        switch identifier {
        case .reserved:
            return ReservedCurve()
        case .p256:
            return P256Curve()
        case .p384:
            return P384Curve()
        case .p521:
            return P521Curve()
        case .x25519:
            return X25519Curve()
        case .x448:
            return X448Curve()
        case .ed25519:
            return Ed25519Curve()
        case .ed448:
            return Ed448Curve()
        case .secp256k1:
            return SECP256K1Curve()
        }
    }
}


// MARK: - Concrete Curve Implementations

public class ReservedCurve: CoseCurve {
    public init() {
        super.init(
            identifier: .reserved,
            fullname: "RESERVED",
            size: 0
        )
    }
}

public class P256Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .p256,
            fullname: "P_256",
            size: 32,
            curveType: .SECP256R1,
            keyType: .ktyEC2
        )
    }
}

public class P384Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .p384,
            fullname: "P_384",
            size: 48,
            curveType: .SECP384R1,
            keyType: .ktyEC2
        )
    }
}

public class P521Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .p521,
            fullname: "P_521",
            size: 66,
            curveType: .SECP521R1,
            keyType: .ktyEC2
        )
    }
}

public class X25519Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .x25519,
            fullname: "X25519",
            size: 32,
            curveType: .X25519,
            keyType: .ktyOKP
        )
    }
}

public class X448Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .x448,
            fullname: "X448",
            size: 57,
            curveType: .X448,
            keyType: .ktyOKP
        )
    }
}

public class Ed25519Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .ed25519,
            fullname: "ED25519",
            size: 32,
            curveType: .ED25519,
            keyType: .ktyOKP
        )
    }
}

public class Ed448Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .ed448,
            fullname: "ED448",
            size: 57,
            curveType: .ED448,
            keyType: .ktyOKP
        )
    }
}

public class SECP256K1Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .secp256k1,
            fullname: "SECP256K1",
            size: 32,
            curveType: .SECP256K1,
            keyType: .ktyEC2
        )
    }
}
