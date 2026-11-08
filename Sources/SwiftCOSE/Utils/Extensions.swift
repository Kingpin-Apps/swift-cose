import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import OrderedCollections
import CBORCodable
import CryptoSwift


// MARK: - Curve25519.KeyAgreement.PublicKey Extensions
public extension Curve25519.KeyAgreement.PublicKey {
    /// Creates a Curve25519 public key for key agreement from an ANSI x9.63
    /// representation.
    ///
    /// - Parameters:
    ///   - x963Representation: An ANSI x9.63 representation of the key.
    /// - Throws: An error if the x9.63 representation is invalid.
    init(x963Representation: some ContiguousBytes) throws {
        let representation = x963Representation.withUnsafeBytes { Data($0) }
        
        // Validate the length: Curve25519 public keys are 32 bytes
        guard representation.count == 33, representation.first == 0x04 else {
            throw CryptoKitError.incorrectParameterSize
        }
        
        // Extract X coordinate from the representation
        let xBytes = representation.dropFirst() // Skip the 0x04 prefix
        
        // Curve25519 only uses X coordinate (Edwards form Y coordinate is implied)
        self = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: xBytes)
    }
}

// MARK: - P256.Signing.PrivateKey Extensions
public extension P256.Signing.PrivateKey {
    func publicKeyCoordinates() -> (x: Data, y: Data) {
        let x963 = self.publicKey.x963Representation
        let x = x963.subdata(in: 1..<33)
        let y = x963.subdata(in: 33..<65)
        return (x, y)
    }
}

// MARK: - Data Extensions
extension Data {
    var toBytes: [UInt8] {
        return [UInt8](self)
    }
    
    var toHex: String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
    
    /// Parses these bytes as one CBOR data item.
    ///
    /// Only use this on bytes that already hold CBOR. To put raw bytes (a
    /// payload, a signature or an encoded header) into a message, wrap them
    /// with `CBOR.byteString(_:)` instead.
    var toCBOR: CBOR {
        get throws {
            return try CBORSerialization.cbor(from: self)
        }
    }
    
    func toInt() -> Int {
        return reduce(0) { ($0 << 8) | Int($1) }
    }

    static func fromInt(_ value: Int, length: Int) -> Data {
        var num = value
        var data = Data()
        for _ in 0..<length {
            data.insert(UInt8(num & 0xff), at: 0)
            num >>= 8
        }
        return data
    }
    
    static func randomBytes(count: Int) -> Data {
        var data = Data(count: count)
        #if canImport(Security)
        _ = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        #else
        var rng = SystemRandomNumberGenerator()
        for i in 0..<count {
            data[i] = UInt8.random(in: 0...255, using: &rng)
        }
        #endif
        return data
    }
    
    init?(hexString: String) {
        let length = hexString.count / 2
        var data = Data(capacity: length)
        var index = hexString.startIndex
        for _ in 0..<length {
            let nextIndex = hexString.index(index, offsetBy: 2)
            if let byte = UInt8(hexString[index..<nextIndex], radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
            index = nextIndex
        }
        self = data
    }
}

// MARK: - Int Extensions
extension Int {
    func toData() -> Data {
        var value = self
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}

// MARK: - Array Extensions
extension Array where Element == UInt8 {
    var toData: Data {
        return Data(self)
    }
}

// MARK: - String Extensions
extension String {
    var hexStringToData: Data {
        var tempHex = self
        
        // Ensure string length is even
        if tempHex.count % 2 != 0 {
            tempHex = "0" + tempHex
        }
        
        let cleanHex = tempHex.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        var bytes = [UInt8]()
        var currentIndex = cleanHex.startIndex
        
        while currentIndex < cleanHex.endIndex {
            let nextIndex = cleanHex.index(currentIndex, offsetBy: 2, limitedBy: cleanHex.endIndex) ?? cleanHex.endIndex
            let byteString = String(cleanHex[currentIndex..<nextIndex])
            if let byte = UInt8(byteString, radix: 16) {
                bytes.append(byte)
            }
            currentIndex = nextIndex
        }
        
        return Data(bytes)
    }
}

// MARK: - OrderedDictionary Extensions
extension OrderedDictionary {
    func mapKeysToCbor() throws -> OrderedDictionary<CBOR, CBOR> {
        try self.reduce(into: [:]) { result, element in
            result[try CBOR.fromCoseValue(element.key)] = try CBOR.fromCoseValue(element.value)
        }
    }
}

// MARK: - Dictionary Extensions
extension Dictionary where Key == AnyHashable, Value == Any {
    func mapKeysToCbor() throws -> OrderedDictionary<CBOR, CBOR> {
        try self.reduce(into: [:]) { result, element in
            result[try CBOR.fromCoseValue(element.key)] = try CBOR.fromCoseValue(element.value)
        }
    }
}
extension Dictionary where Key == AnyHashable, Value == CoseHeaderAttribute {
    func mapKeysToCbor() throws -> OrderedDictionary<CBOR, CBOR> {
        try self.reduce(into: [:]) { result, element in
            result[try CBOR.fromCoseValue(element.key)] = try CBOR.fromCoseValue(element.value)
        }
    }
}

// MARK: - CBOR Extensions
extension CBOR {
    /// Converts a header or key value to CBOR.
    ///
    /// - Throws: When the value has no CBOR form. It used to become CBOR
    ///   null, which silently changed what was signed or sent.
    static func fromCoseValue(_ value: Any) throws -> CBOR {
        // Map keys arrive as AnyHashable; convert the wrapped value, or an
        // integer key could bridge to a Bool on Apple platforms.
        if let hashable = value as? AnyHashable, !(hashable.base is AnyHashable) {
            return try fromCoseValue(hashable.base)
        }
        if let cborValue = value as? CBOR {
            return cborValue
        } else if let stringValue = value as? String {
            return .textString(stringValue)
        } else if Swift.type(of: value) == Bool.self, let boolValue = value as? Bool {
            // Exact type checks: on Apple platforms an Int in an Any casts
            // to Bool or Double through NSNumber bridging.
            return .boolean(boolValue)
        } else if let integer = value as? any BinaryInteger {
            // Every integer width is a CBOR integer (UInt8 and Int8 used to
            // become simple values).
            if let signed = Int64(exactly: integer) {
                return signed >= 0 ? .unsignedInt(UInt64(signed)) : .negativeInt(UInt64(-1 - signed))
            } else if let unsigned = UInt64(exactly: integer) {
                return .unsignedInt(unsigned)
            }
            throw CoseError.valueError("Integer \(integer) does not fit in CBOR")
        } else if let dataValue = value as? Data {
            return .byteString(dataValue)
        } else if Swift.type(of: value) == Float.self, let floatValue = value as? Float {
            return .float(floatValue)
        } else if Swift.type(of: value) == Double.self, let doubleValue = value as? Double {
            return .double(doubleValue)
        } else if let arrayValue = value as? [Any] {
            return .array(try arrayValue.map { try CBOR.fromCoseValue($0) })
        } else if let attrValue = value as? CoseAttribute {
            if let identifier = attrValue.identifier {
                return CBOR(identifier)
            } else if let fullname = attrValue.fullname {
                return .textString(fullname)
            }
            throw CoseError.valueError("\(attrValue) has no identifier or name")
        } else if let keyValue = value as? CoseKey {
            // A COSE_Key carried in a header, e.g. an ephemeral key.
            return .map(try keyValue.store.mapKeysToCbor())
        } else if let dictValue = value as? OrderedDictionary<CoseHeaderAttribute, Any> {
            return .map(try dictValue.mapKeysToCbor())
        } else if let dictValue = value as? [AnyHashable: CoseHeaderAttribute] {
            return .map(try dictValue.mapKeysToCbor())
        } else if let dictValue = value as? [AnyHashable: Any] {
            return .map(try dictValue.mapKeysToCbor())
        }
        throw CoseError.valueError("Cannot encode a value of type \(type(of: value)) as CBOR")
    }
}

// MARK: - CS.BigUInt Extensions
extension CS.BigUInt {
    var toData: Data {
        var data = Data()
        var value = self
        while value > 0 {
            let byte = UInt8(value & 0xFF)
            data.insert(byte, at: 0) // Insert at the beginning for big-endian representation
            value >>= 8
        }
        return data
    }
}


// MARK: - RSA Extensions
extension RSA {
    public struct PrivateKey {
        let data: Data
        public init (data: Data) throws {
            self.data = data
        }
    }
    public struct PublicKey {
        let data: Data
        public init (data: Data) throws {
            self.data = data
        }
    }
    
    func privateKey() throws -> PrivateKey {
        return try PrivateKey(data: self.externalRepresentation())
    }
    
    func publicKey() throws -> PublicKey {
        return try PublicKey(data: self.publicKeyExternalRepresentation())
    }
}

