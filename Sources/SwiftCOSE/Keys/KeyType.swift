import Foundation

public enum KeyTypeIdentifier: Int, CaseIterable, Sendable {
    case reserved = 0
    case okp = 1
    case ec2 = 2
    case rsa = 3
    case symmetric = 4
    
    public static func fromKTY(_ kty: KTY) throws -> KeyTypeIdentifier {
        if let fullname = kty.fullname {
            guard let id = KeyTypeIdentifier.fromFullName(fullname) else {
                throw CoseError.invalidAlgorithm("Unknown fullname \(fullname)")
            }
            return id
        } else if let identifier = kty.identifier {
            guard let id = KeyTypeIdentifier(rawValue: identifier) else {
                throw CoseError.invalidAlgorithm("Unknown identifier \(identifier)")
            }
            return id
        } else {
            throw CoseError
                .invalidKeyType("Key Type not found in KTY instance")
        }
    }
    
    /// Returns the appropriate `KeyTypeIdentifier` for the given fullname.
    /// - Parameter fullname: The string fullname of the key type.
    /// - Returns: The corresponding `KeyTypeIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullname: String) -> KeyTypeIdentifier? {
        switch fullname.uppercased() {
        case "RESERVED":
            return .reserved
        case "OKP":
            return .okp
        case "EC2":
            return .ec2
        case "RSA":
            return .rsa
        case "SYMMETRIC":
            return .symmetric
        default:
            return nil
        }
    }
}

// Base class for key types
public class KTY: CoseAttribute {
    public init(
        identifier: KeyTypeIdentifier,
        fullname: String
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
    
    /// Returns the appropriate `KTY` instance for the given identifier or name.
   /// - Parameter attribute: The identifier or name of the key type.
   /// - Returns: A specific `KTY` instance.
   public static func fromId(for attribute: Any) throws -> KTY {
       switch attribute {
           case let id as Int:
               // If the identifier is an Int, convert it to KeyTypeIdentifier
               guard let type = KeyTypeIdentifier(rawValue: id) else {
                   throw CoseError.invalidKeyType("Unknown type identifier")
               }
               return getInstance(for: type)
           case let id as UInt64:
               // Ensure UInt64 fits within Int bounds
               guard id <= UInt64(Int.max) else {
                   throw CoseError.invalidKeyType("UInt64 value exceeds Int max limit")
               }
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
               
           case let kty as KTY:
               // If the identifier is already a KTY get the instance directly
               return kty

           default:
               throw CoseError.invalidKeyType("Unsupported identifier type. Must be Int, String, or KeyTypeIdentifier")
       }
   }

   /// Returns the appropriate `KTY` instance for the given identifier.
   /// - Parameter identifier: The `KeyTypeIdentifier` to create an instance for.
   /// - Returns: A specific `KTY` instance.
   public static func getInstance(for identifier: KeyTypeIdentifier) -> KTY {
       switch identifier {
       case .reserved:
           return KtyReserved()
       case .okp:
           return KtyOKP()
       case .ec2:
           return KtyEC2()
       case .rsa:
           return KtyRSA()
       case .symmetric:
           return KtySymmetric()
       }
   }
}

// Subclass for RESERVED key type
public class KtyReserved: KTY {
    public init() {
        super.init(
            identifier: .reserved,
            fullname: "RESERVED"
        )
    }
}

// Subclass for OKP key type
public class KtyOKP: KTY {
    public init() {
        super.init(
            identifier: .okp,
            fullname: "OKP"
        )
    }
}

// Subclass for EC2 key type
public class KtyEC2: KTY {
    public init() {
        super.init(
            identifier: .ec2,
            fullname: "EC2"
        )
    }
}

// Subclass for RSA key type
public class KtyRSA: KTY {
    public init() {
        super.init(
            identifier: .rsa,
            fullname: "RSA"
        )
    }
}

// Subclass for SYMMETRIC key type
public class KtySymmetric: KTY {
    public init() {
        super.init(
            identifier: .symmetric,
            fullname: "SYMMETRIC"
        )
    }
}
