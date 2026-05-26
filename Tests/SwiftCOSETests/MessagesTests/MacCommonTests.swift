import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct MacCommonTests {
    
    // MARK: - Initialization Tests
    
    @Test func testMacCommonInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): AESMAC12864(),
            IV(): Data([0x05, 0x06, 0x07, 0x08])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/cbor"
        ]
        
        let payload = Data("Mac Payload".utf8)
        let externalAAD = Data("Mac AAD".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 16))
        
        let macMessage = MacCommon(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: symmetricKey
        )
        
        #expect(macMessage.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(macMessage.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(macMessage.payload == payload, "Payload should match the initialized value.")
        #expect(macMessage.externalAAD == externalAAD, "External AAD should match the initialized value.")
        #expect(macMessage.key === symmetricKey, "Key should match the initialized key.")
    }
}
