import Foundation
import OrderedCollections
import CBORCodable

public struct Headers {
    public var protected: Data?
    public var unprotected: Dictionary<AnyHashable, Any>
}

public enum CoseHeaderIdentifier: Int, CaseIterable, Sendable {
    case reserved = 0
    case algorithm = 1
    case critical = 2
    case contentType = 3
    case kid = 4
    case iv = 5
    case partialIV = 6
    case counterSignature = 7
    case counterSignature0 = 9
    case kidContext = 10
    case x5bag = 32
    case x5chain = 33
    case x5t = 34
    case x5u = 35
    case ephemeralKey = -1
    case staticKey = -2
    case staticKeyID = -3
    case salt = -20
    case partyUID = -21
    case partyUNonce = -22
    case partyUOther = -23
    case partyVID = -24
    case partyVNonce = -25
    case partyVOther = -26
    case suppPubOther = -998
    case suppPrivOther = -999
    
    /// Returns the appropriate `CoseHeaderIdentifier` for the given fullname.
    /// - Parameter fullname: The string fullname of the header.
    /// - Returns: The corresponding `CoseHeaderIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullname: String) -> CoseHeaderIdentifier? {
        switch fullname.uppercased() {
            case "RESERVED": return .reserved
            case "ALG": return .algorithm
            case "CRITICAL": return .critical
            case "CONTENT_TYPE": return .contentType
            case "KID": return .kid
            case "IV": return .iv
            case "PARTIAL_IV": return .partialIV
            case "COUNTER_SIGN": return .counterSignature
            case "COUNTER_SIGN0": return .counterSignature0
            case "KID_CONTEXT": return .kidContext
            case "X5_BAG": return .x5bag
            case "X5_CHAIN": return .x5chain
            case "X5_T": return .x5t
            case "X5_U": return .x5u
            case "EPHEMERAL_KEY": return .ephemeralKey
            case "STATIC_KEY": return .staticKey
            case "STATIC_KEY_ID": return .staticKeyID
            case "SALT": return .salt
            case "PARTY_U_ID": return .partyUID
            case "PARTY_U_NONCE": return .partyUNonce
            case "PARTY_U_OTHER": return .partyUOther
            case "PARTY_V_ID": return .partyVID
            case "PARTY_V_NONCE": return .partyVNonce
            case "PARTY_V_OTHER": return .partyVOther
            case "SUPP_PUB_OTHER": return .suppPubOther
            case "SUPP_PRIV_OTHER": return .suppPrivOther
            default: return nil
        }
    }
}

open class CoseHeaderAttribute: CoseAttribute {
    public init(
        identifier: CoseHeaderIdentifier,
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
        customIdentifier: Int?,
        fullname: String?,
        valueParser: ((Any) throws -> Any)? = nil
    ) {
        super.init(
            identifier: customIdentifier,
            fullname: fullname,
            valueParser: valueParser
        )
    }
    
    
    public static func fromId(for attribute: Any) throws -> CoseHeaderAttribute {
        switch attribute {
            case let id as any BinaryInteger:
                // Accept any integer width — on swift-corelibs-foundation (Linux/Windows),
                // CBOR decode yields UInt64/Int64 keys that do not bridge to Int via `as?`.
                guard let intId = exactInt(id), let hdr = CoseHeaderIdentifier(rawValue: intId) else {
                    throw CoseError.invalidHeader("Unknown header identifier")
                }
                return getInstance(for: hdr)
                
            case let id as String:
                // If the identifier is a String, attempt to match it to a CoseHeaderIdentifier
                guard let hdr = CoseHeaderIdentifier.fromFullName(id) else {
                    throw CoseError.invalidHeader("Unknown header fullname")
                }
                return getInstance(for: hdr)
                
            case let hdr as CoseHeaderIdentifier:
                // If the identifier is already a CoseHeaderIdentifier, get the instance directly
                return getInstance(for: hdr)
                
            default:
                throw CoseError.invalidHeader("Invalid header identifier")
        }
    }
    
    public static func getInstance(for identifier: CoseHeaderIdentifier) -> CoseHeaderAttribute {
        switch identifier {
            case .reserved: return Reserved()
            case .algorithm: return Algorithm()
            case .critical: return Critical()
            case .contentType: return ContentType()
            case .kid: return KID()
            case .iv: return IV()
            case .partialIV: return PartialIV()
            case .counterSignature: return CounterSignature()
            case .counterSignature0: return CounterSignature0()
            case .kidContext: return KIDContext()
            case .x5bag: return X5bag()
            case .x5chain: return X5chain()
            case .x5t: return X5t()
            case .x5u: return X5u()
            case .ephemeralKey: return EphemeralKey()
            case .staticKey: return StaticKey()
            case .staticKeyID: return StaticKeyID()
            case .salt: return Salt()
            case .partyUID: return PartyUID()
            case .partyUNonce: return PartyUNonce()
            case .partyUOther: return PartyUOther()
            case .partyVID: return PartyVID()
            case .partyVNonce: return PartyVNonce()
            case .partyVOther: return PartyVOther()
            case .suppPubOther: return SuppPubOther()
            case .suppPrivOther: return SuppPrivOther()
        }
    }
}

public final class Reserved: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .reserved, fullname: "RESERVED")
    }
}

public final class Algorithm: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .algorithm, fullname: "ALG")
    }
}

public final class Critical: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .critical, fullname: "CRITICAL", valueParser: critIsArray)
    }
}

public final class ContentType: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .contentType, fullname: "CONTENT_TYPE", valueParser: contentTypeIsUIntOrTstr)
    }
}

public final class KID: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .kid, fullname: "KID", valueParser: isBstr)
    }
}

public final class IV: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .iv, fullname: "IV", valueParser: isBstr)
    }
}

public final class PartialIV: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partialIV, fullname: "PARTIAL_IV", valueParser: isBstr)
    }
}

public final class CounterSignature: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .counterSignature, fullname: "COUNTER_SIGN")
    }
}

public final class CounterSignature0: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .counterSignature0, fullname: "COUNTER_SIGN0", valueParser: isBstr)
    }
}

public final class KIDContext: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .kidContext, fullname: "KID_CONTEXT", valueParser: isBstr)
    }
}

public final class X5bag: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .x5bag, fullname: "X5_BAG")
    }
}

public final class X5chain: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .x5chain, fullname: "X5_CHAIN")
    }
}

public final class X5t: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .x5t, fullname: "X5_T")
    }
}

public final class X5u: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .x5u, fullname: "X5_U")
    }
}

public final class EphemeralKey: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .ephemeralKey, fullname: "EPHEMERAL_KEY", valueParser: isCoseKey)
    }
}

public final class StaticKey: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .staticKey, fullname: "STATIC_KEY", valueParser: isCoseKey)
    }
}

public final class StaticKeyID: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .staticKeyID, fullname: "STATIC_KEY_ID")
    }
}

public final class Salt: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .salt, fullname: "SALT")
    }
}

public final class PartyUID: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyUID, fullname: "PARTY_U_ID")
    }
}

public final class PartyUNonce: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyUNonce, fullname: "PARTY_U_NONCE")
    }
}

public final class PartyUOther: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyUOther, fullname: "PARTY_U_OTHER")
    }
}

public final class PartyVID: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyVID, fullname: "PARTY_V_ID")
    }
}

public final class PartyVNonce: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyVNonce, fullname: "PARTY_V_NONCE")
    }
}

public final class PartyVOther: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyVOther, fullname: "PARTY_V_OTHER")
    }
}

public final class SuppPubOther: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .suppPubOther, fullname: "SUPP_PUB_OTHER")
    }
}

public final class SuppPrivOther: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .suppPrivOther, fullname: "SUPP_PRIV_OTHER")
    }
}

public func isBstr(_ value: Any) throws -> Any {
    guard let _ = value as? Data else {
        throw CoseError.invalidKIDValue("Key ID must be a byte string")
    }
    return value
}

/// Turns a decoded COSE_Key map in a header into a `CoseKey`.
func isCoseKey(_ value: Any) throws -> Any {
    if value is CoseKey {
        return value
    }
    let entries: [(AnyHashable, Any)]
    if let map = value as? OrderedDictionary<AnyHashable, Any> {
        entries = map.map { ($0.key, $0.value) }
    } else if let map = value as? OrderedDictionary<AnyHashable, Any?> {
        entries = map.compactMap { key, value in value.map { (key, $0) } }
    } else if let map = value as? [AnyHashable: Any] {
        entries = map.map { ($0.key, $0.value) }
    } else {
        throw CoseError.invalidHeader("A key header must be a COSE_Key map")
    }
    
    // Decoded CBOR integers arrive as UInt64/Int64; key lookups use Int.
    func normalize(_ value: AnyHashable) -> AnyHashable {
        if let v = value.base as? UInt64, let i = Int(exactly: v) { return i }
        if let v = value.base as? Int64, let i = Int(exactly: v) { return i }
        return value
    }
    func normalize(_ value: Any) -> Any {
        if let v = value as? UInt64, let i = Int(exactly: v) { return i }
        if let v = value as? Int64, let i = Int(exactly: v) { return i }
        return value
    }
    var dict: [AnyHashable: Any] = [:]
    for (key, value) in entries {
        dict[normalize(key)] = normalize(value)
    }
    return try CoseKey.fromDictionary(dict)
}

// MARK: - Decoding header maps

/// Converts a decoded CBOR header map into label/value pairs.
///
/// RFC 9052, section 3: labels are integers or text strings and must not
/// repeat. Anything else throws instead of trapping, because the bytes come
/// from the network.
func headerMap(from cbor: CBOR) throws -> OrderedDictionary<AnyHashable, Any> {
    let entries: OrderedDictionary<CBOR, CBOR>
    switch cbor {
        case .map(let map), .indefiniteMap(let map):
            entries = map
        default:
            throw CoseError.invalidHeader("A header must be a CBOR map")
    }
    
    var result = OrderedDictionary<AnyHashable, Any>()
    for (key, value) in entries {
        let label: AnyHashable
        switch key {
            case .unsignedInt(let u):
                guard let i = Int(exactly: u) else {
                    throw CoseError.invalidHeader("Header label \(u) is out of range")
                }
                label = i
            case .negativeInt(let n):
                guard let i = Int(exactly: n), i < Int.max else {
                    throw CoseError.invalidHeader("Header label is out of range")
                }
                label = -1 - i
            case .textString(let text):
                label = text
            default:
                throw CoseError.invalidHeader("Header labels must be integers or text strings")
        }
        guard result[label] == nil else {
            throw CoseError.invalidHeader("Duplicate header label \(label)")
        }
        result[label] = headerValue(value)
    }
    return result
}

/// Converts a decoded CBOR header value into a Swift value, keeping
/// integers as `Int` where they fit. Values with no Swift equivalent (such
/// as `null`) stay as `CBOR`, so the header parsers reject them.
func headerValue(_ value: CBOR) -> Any {
    switch value {
        case .unsignedInt(let u):
            if let i = Int(exactly: u) { return i }
            return u
        case .negativeInt(let n):
            if let i = Int(exactly: n), i < Int.max { return -1 - i }
            return value
        case .map, .indefiniteMap:
            if let map = try? headerMap(from: value) { return map }
            return value.unwrapped ?? value
        default:
            return value.unwrapped ?? value
    }
}

public func critIsArray(_ value: Any) throws -> Any {
    guard let array = value as? [Any], !array.isEmpty,
          array.allSatisfy({ $0 is any BinaryInteger || $0 is String }) else {
        throw CoseError.invalidCriticalValue("Critical values must be a non-empty array of integers or strings")
    }
    return value
}

fileprivate func exactInt<T: BinaryInteger>(_ value: T) -> Int? {
    Int(exactly: value)
}

public func contentTypeIsUIntOrTstr(_ value: Any) throws -> Any {
    // Decoded CBOR unsigned integers arrive as UInt64; normalise to Int.
    if let intVal = value as? any BinaryInteger, let normalized = exactInt(intVal), normalized >= 0 {
        return normalized
    } else if value is String {
        return value
    }
    throw CoseError.invalidContentType("Content type must be a non-negative integer or text string")
}
