import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct EncCommonTests {
    
    // MARK: - Initialization Tests
    
    @Test func testEncCommonInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A128GCM(),
            IV(): Data([0x01, 0x02, 0x03, 0x04])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/cbor"
        ]
        
        let payload = Data("Enc Payload".utf8)
        let externalAAD = Data("Enc AAD".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 16))
        
        let enc0Message = EncCommon(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: symmetricKey
        )
        
        #expect(enc0Message.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(enc0Message.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(enc0Message.payload == payload, "Payload should match the initialized value.")
        #expect(enc0Message.externalAAD == externalAAD, "External AAD should match the initialized value.")
        #expect(enc0Message.key === symmetricKey, "Key should match the initialized key.")
    }
}
