import Testing
import Foundation
import CryptoKit
import CryptoSwift
import CBORCodable
import SwiftCurve448
@testable import SwiftCOSE

struct ExtensionsTests {

    // MARK: - Curve25519 KeyAgreement PublicKey Tests
    @Test
    func testCurve25519PublicKeyFromX963Representation() async throws {
        let rawBytes = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let x963Representation = Data([0x04] + rawBytes)

        let derivedPublicKey = try Curve25519.KeyAgreement.PublicKey(x963Representation: x963Representation)
        
        #expect(derivedPublicKey.rawRepresentation == rawBytes)
    }
    
    @Test
    func testInvalidCurve25519PublicKey() async throws {
        let invalidData = Data(repeating: 0x00, count: 10) // Invalid length
        let x963Representation = Data([0x04] + invalidData)

        #expect(throws: CryptoKitError.self) {
            let _ = try Curve25519.KeyAgreement.PublicKey(x963Representation: x963Representation)
        }
    }
    
    // MARK: - P256 PrivateKey Tests
    @Test
    func testP256PublicKeyCoordinates() async throws {
        let privateKey = P256.Signing.PrivateKey()
        let (x, y) = privateKey.publicKeyCoordinates()
        
        let x963Representation = privateKey.publicKey.x963Representation
        let expectedX = x963Representation.subdata(in: 1..<33)
        let expectedY = x963Representation.subdata(in: 33..<65)
        
        #expect(x == expectedX)
        #expect(y == expectedY)
    }
    
    // MARK: - Data Extension Tests
    @Test
    func testDataToHex() async throws {
        let data = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let hexString = data.toHex
        
        #expect(hexString == "deadbeef")
    }
    
    @Test
    func testHexStringToData() async throws {
        let hexString = "deadbeef"
        let data = Data(hexString: hexString)
        
        #expect(data != nil)
        #expect(data!.toHex == hexString)
    }
    
    @Test
    func testRandomBytes() async throws {
        let randomData = Data.randomBytes(count: 16)
        
        #expect(randomData.count == 16)
    }
    
    @Test
    func testIntToData() async throws {
        let intValue = 10
        let data = intValue.toData()
        
        let expectedData = Data([0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        #expect(data == expectedData)
    }
    
    @Test
    func testDataToInt() async throws {
        let data = Data([0x00, 0x01])
        let intValue = data.toInt()
        
        #expect(intValue == 1)
    }
    
    // MARK: - String Extension Tests
    @Test
    func testStringHexConversion() async throws {
        let hexString = "0a1b2c"
        let data = hexString.hexStringToData
        
        #expect(data.toHex == "0a1b2c")
    }
    
    @Test
    func testInvalidHexString() async throws {
        let invalidHexString = "xyz"
        let data = invalidHexString.hexStringToData
        
        #expect(data.count == 0)
    }
    
    // MARK: - CBOR Dictionary Extension Tests
    @Test
    func testMapKeysToCBOR() async throws {
        let dictionary: [AnyHashable: Any] = ["key": "value", 1: 42]
        let cborDict = dictionary.mapKeysToCbor
        
        #expect(cborDict[CBOR("key")] == CBOR.textString("value"))
        #expect(cborDict[CBOR.unsignedInt(1)] == CBOR.unsignedInt(42))
    }
    
    // MARK: - RSA Key Tests
    @Test
    func testRSAKeyConversion() async throws {
        let rsaPrivateKey = try RSA.PrivateKey(data: Data([0x01, 0x02]))
        let rsaPublicKey = try RSA.PublicKey(data: Data([0x03, 0x04]))
        
        let privateKeyData = rsaPrivateKey.data
        let publicKeyData = rsaPublicKey.data
        
        #expect(privateKeyData == Data([0x01, 0x02]))
        #expect(publicKeyData == Data([0x03, 0x04]))
    }
}
