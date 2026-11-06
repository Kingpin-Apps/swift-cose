import Testing
import Foundation
@testable import SwiftCOSE

struct AesMacAlgorithmTests {
    
    @Test func testAESMAC12864() async throws {
        let aesMac = AESMAC12864()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesMac.keyLength
        )
        let data = "Test Data for MAC".data(using: .utf8)!
        
        let tag = try aesMac.computeTag(key: key, data: data)
        let isValid = try aesMac.verifyTag(key: key, tag: tag, data: data)
        
        #expect(isValid, "Tag verification failed for AESMAC12864.")
    }
    
    @Test func testAESMAC25664() async throws {
        let aesMac = AESMAC25664()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesMac.keyLength
        )
        let data = "Test Data 256-bit".data(using: .utf8)!
        
        let tag = try aesMac.computeTag(key: key, data: data)
        let isValid = try aesMac.verifyTag(key: key, tag: tag, data: data)
        
        #expect(isValid, "Tag verification failed for AESMAC25664.")
    }
    
    @Test func testAESMAC128128() async throws {
        let aesMac = AESMAC128128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesMac.keyLength
        )
        let data = "Longer test data for MAC 128-bit".data(using: .utf8)!
        
        let tag = try aesMac.computeTag(key: key, data: data)
        let isValid = try aesMac.verifyTag(key: key, tag: tag, data: data)
        
        #expect(isValid, "Tag verification failed for AESMAC128128.")
    }
    
    @Test func testAESMAC256128() async throws {
        let aesMac = AESMAC256128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesMac.keyLength
        )
        let data = "Another test for 256-bit MAC".data(using: .utf8)!
        
        let tag = try aesMac.computeTag(key: key, data: data)
        let isValid = try aesMac.verifyTag(key: key, tag: tag, data: data)
        
        #expect(isValid, "Tag verification failed for AESMAC256128.")
    }
    
    @Test func testAESMACVerifyTagFailure() async throws {
        let aesMac = AESMAC128128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesMac.keyLength
        )
        let data = "Test data".data(using: .utf8)!
        let tamperedData = "Tampered data".data(using: .utf8)!
        
        let tag = try aesMac.computeTag(key: key, data: data)
        let isValid = try aesMac.verifyTag(
            key: key,
            tag: tag,
            data: tamperedData
        )
        
        #expect(!isValid, "Verification should fail for tampered data.")
    }
    
    /// COSE WG aes-wrap-examples/aes-wrap-128-01.json: the MAC_structure
    /// (ToMac_hex) and CEK give the published AES-MAC-128/64 tag.
    @Test func testAESMAC12864KnownAnswer() async throws {
        let key = try CoseSymmetricKey(k: Data(hex: "DDDC08972DF9BE62855291A17A1B4CF7"))
        let toMac = Data(hex: "84634D414343A1010E4054546869732069732074686520636F6E74656E742E")
        let tag = try AESMAC12864().computeTag(key: key, data: toMac)
        #expect(tag == Data(hex: "36F5AFAF0BAB5D43"))
    }
    
    @Test func testAESMACTagLengths() async throws {
        let key = try CoseSymmetricKey(k: Data(repeating: 1, count: 16))
        #expect(try AESMAC12864().computeTag(key: key, data: Data([1, 2, 3])).count == 8)
        #expect(try AESMAC128128().computeTag(key: key, data: Data(count: 32)).count == 16)
    }
}
