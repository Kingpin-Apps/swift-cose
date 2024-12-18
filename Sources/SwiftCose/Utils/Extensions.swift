import Foundation
import CryptoKit
import OrderedCollections
import PotentCBOR
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
    
    var toCBOR: CBOR {
        return try! CBORSerialization.cbor(from: self)
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
    var hexStringToData: Data? {
        var data = Data()
        var tempHex = self
        
        // Ensure string length is even
        if tempHex.count % 2 != 0 {
            tempHex = "0" + tempHex
        }
        
        // Iterate through the string in pairs of two
        var index = tempHex.startIndex
        while index < tempHex.endIndex {
            let nextIndex = tempHex.index(index, offsetBy: 2)
            let byteString = tempHex[index..<nextIndex]
            if let byte = UInt8(byteString, radix: 16) {
                data.append(byte)
            } else {
                return nil // Invalid hex string
            }
            index = nextIndex
        }
        return data
    }
}

// MARK: - Dictionary Extensions
extension Dictionary where Key == String, Value == Any {
    var mapKeysToCbor: OrderedDictionary<CBOR, CBOR> {
        return self.reduce(into: [:]) { result, element in
            result[CBOR(element.key)] = CBOR.fromAny(element.value)
        }
    }
}

// MARK: - Dictionary Extensions
extension CBOR {
    static func fromAny(_ value: Any) -> CBOR {
        if let stringValue = value as? String {
            return .utf8String(stringValue)
        } else if let intValue = value as? Int {
            return .unsignedInt(UInt64(intValue))
        } else if let dataValue = value as? Data {
            return .byteString(dataValue)
        } else if let dictValue = value as? [String: Any] {
            return .map(dictValue.mapKeysToCbor)
        } else {
            return .null
        }
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