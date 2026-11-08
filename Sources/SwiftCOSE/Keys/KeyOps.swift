import Foundation

public enum KeyOpsIdentifier: Int, CaseIterable, Sendable {
    case sign = 1
    case verify = 2
    case encrypt = 3
    case decrypt = 4
    case wrap = 5
    case unwrap = 6
    case deriveKey = 7
    case deriveBits = 8
    case macCreate = 9
    case macVerify = 10
    
    /// Returns the appropriate `KeyOpsIdentifier` for the given fullname.
    /// - Parameter fullname: The string fullname of the key operation.
    /// - Returns: The corresponding `KeyOpsIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullname: String) -> KeyOpsIdentifier? {
        switch fullname.uppercased() {
            case "SIGN":
                return .sign
            case "VERIFY":
                return .verify
            case "ENCRYPT":
                return .encrypt
            case "DECRYPT":
                return .decrypt
            case "WRAP":
                return .wrap
            case "UNWRAP":
                return .unwrap
            case "DERIVE_KEY":
                return .deriveKey
            case "DERIVE_BITS":
                return .deriveBits
            case "MAC_CREATE":
                return .macCreate
            case "MAC_VERIFY":
                return .macVerify
            default:
                return nil
        }
    }
}
    
public class KeyOps: CoseAttribute {
    public init(
        identifier: KeyOpsIdentifier,
        fullname: String
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
    
    /// Returns the appropriate `KeyOps` instance for the given identifier or name.
    /// - Parameter attribute: The identifier or name of the key operation.
    /// - Returns: A specific `KeyOps` instance.
    public static func fromId(for attribute: Any) throws -> KeyOps {
        switch attribute {
            case let id as Int:
                // If the identifier is an Int, convert it to KeyOpsIdentifier
                guard let op = KeyOpsIdentifier(rawValue: id) else {
                    throw CoseError.invalidKeyOps("Unknown operation identifier")
                }
                return getInstance(for: op)
                
            case let id as any BinaryInteger:
                // CBOR integers can decode as UInt64 or Int64.
                guard let value = Int(exactly: id), let op = KeyOpsIdentifier(rawValue: value) else {
                    throw CoseError.invalidKeyOps("Unknown operation identifier")
                }
                return getInstance(for: op)

            case let name as String:
                // If the identifier is a String, attempt to match it to a KeyOpsIdentifier
                guard let op = KeyOpsIdentifier.fromFullName(name) else {
                    throw CoseError.invalidKeyOps("Unknown operation fullname")
                }
                return getInstance(for: op)
                
            case let op as KeyOpsIdentifier:
                // If the identifier is already a KeyOpsIdentifier, get the instance directly
                return getInstance(for: op)
                    
            case let type as KeyOps:
                return type
                
            default:
                throw CoseError.invalidKeyOps("Unsupported identifier type. Must be Int, String, or KeyOpsIdentifier")
        }
    }

    /// Returns the appropriate `KeyOps` instance for the given identifier.
    /// - Parameter identifier: The `KeyOpsIdentifier` to create an instance for.
    /// - Returns: A specific `KeyOps` instance.
    public static func getInstance(for identifier: KeyOpsIdentifier) -> KeyOps {
        switch identifier {
        case .sign:
            return SignOp()
        case .verify:
            return VerifyOp()
        case .encrypt:
            return EncryptOp()
        case .decrypt:
            return DecryptOp()
        case .wrap:
            return WrapOp()
        case .unwrap:
            return UnwrapOp()
        case .deriveKey:
            return DeriveKeyOp()
        case .deriveBits:
            return DeriveBitsOp()
        case .macCreate:
            return MacCreateOp()
        case .macVerify:
            return MacVerifyOp()
        }
    }
}


public class SignOp: KeyOps {
    public init() {
        super.init(
            identifier: .sign,
            fullname: "SIGN"
        )
    }
}

public class VerifyOp: KeyOps {
    public init() {
        super.init(
            identifier: .verify,
            fullname: "VERIFY"
        )
    }
}

public class EncryptOp: KeyOps {
    public init() {
        super.init(
            identifier: .encrypt,
            fullname: "ENCRYPT"
        )
    }
}

public class DecryptOp: KeyOps {
    public init() {
        super.init(
            identifier: .decrypt,
            fullname: "DECRYPT"
        )
    }
}

public class WrapOp: KeyOps {
    public init() {
        super.init(
            identifier: .wrap,
            fullname: "WRAP"
        )
    }
}

public class UnwrapOp: KeyOps {
    public init() {
        super.init(
            identifier: .unwrap,
            fullname: "UNWRAP"
        )
    }
}

public class DeriveKeyOp: KeyOps {
    public init() {
        super.init(
            identifier: .deriveKey,
            fullname: "DERIVE_KEY"
        )
    }
}

public class DeriveBitsOp: KeyOps {
    public init() {
        super.init(
            identifier: .deriveBits,
            fullname: "DERIVE_BITS"
        )
    }
}

public class MacCreateOp: KeyOps {
    public init() {
        super.init(
            identifier: .macCreate,
            fullname: "MAC_CREATE"
        )
    }
}

public class MacVerifyOp: KeyOps {
    public init() {
        super.init(
            identifier: .macVerify,
            fullname: "MAC_VERIFY"
        )
    }
}
