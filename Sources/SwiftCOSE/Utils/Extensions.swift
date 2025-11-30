import Foundation
import CryptoKit
import OrderedCollections
import PotentCBOR
import CryptoSwift
import OpenSSL


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
    
    static func randomBytes(count: Int) -> Data {
        var data = Data(count: count)
        _ = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
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
    var mapKeysToCbor: OrderedDictionary<CBOR, CBOR> {
        return self.reduce(into: [:]) { result, element in
            result[CBOR.fromAny(element.key)] = CBOR.fromAny(element.value)
        }
    }
}

// MARK: - Dictionary Extensions
extension Dictionary where Key == AnyHashable, Value == Any {
    var mapKeysToCbor: OrderedDictionary<CBOR, CBOR> {
        return self.reduce(into: [:]) { result, element in
            result[CBOR.fromAny(element.key)] = CBOR.fromAny(element.value)
        }
    }
}
extension Dictionary where Key == AnyHashable, Value == CoseHeaderAttribute {
    var mapKeysToCbor: OrderedDictionary<CBOR, CBOR> {
        return self.reduce(into: [:]) { result, element in
            result[CBOR.fromAny(element.key)] = CBOR.fromAny(element.value)
        }
    }
}

// MARK: - CBOR Extensions
extension CBOR {
    static func fromAny(_ value: Any) -> CBOR {
        if let stringValue = value as? String {
            return .utf8String(stringValue)
        } else if let intValue = value as? Int {
            return CBOR(intValue)
        } else if let simpleValue = value as? UInt8 {
            return .simple(simpleValue)
        } else if let simpleValue = value as? Int8 {
            return .simple(UInt8(simpleValue))
        } else if let dataValue = value as? Data {
            return .byteString(dataValue)
        } else if let boolValue = value as? Bool {
            return .boolean(boolValue)
        } else if let floatValue = value as? Float {
            return .float(floatValue)
        } else if let doubleValue = value as? Double {
            return .double(doubleValue)
        } else if let arrayValue = value as? [Any] {
            return .array(arrayValue.map { CBOR.fromAny($0) })
        } else if let attrValue = value as? CoseAttribute {
            if let identifier = attrValue.identifier {
                return CBOR(identifier)
            } else if let fullname = attrValue.fullname {
                return .utf8String(fullname)
            } else {
                return .null
            }
        } else if let dictValue = value as? OrderedDictionary<CoseHeaderAttribute, Any> {
            return .map(dictValue.mapKeysToCbor)
        } else if let dictValue = value as? [AnyHashable: CoseHeaderAttribute] {
            return .map(dictValue.mapKeysToCbor)
        } else if let dictValue = value as? [AnyHashable: Any] {
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

// MARK: CS.BigUInt extension

extension BigUInteger {

  public static func getPrime(_ bits: Int = 1024) throws -> BigUInteger? {
      let bn = BN_new()       // Create a new BIGNUM object
      let ctx = BN_CTX_new()  // Create a new BN context for calculations
      
      defer {
          BN_free(bn)
          BN_CTX_free(ctx)
      }
      
      // Generate a prime number with the specified bit length
      if BN_generate_prime_ex(bn, Int32(bits), 1, nil, nil, nil) == 1 {
          // Get the raw bytes from BIGNUM
         let byteCount = (BN_num_bits(bn) + 7) / 8
          var buffer = [UInt8](repeating: 0, count: Int(byteCount))
         
         BN_bn2bin(bn, &buffer)
         
         // Convert to BigUInteger directly from bytes
         return BigUInteger(Data(buffer))
      } else {
          throw CoseError.openSSLError("Failed to generate prime number")
      }
  }
}
