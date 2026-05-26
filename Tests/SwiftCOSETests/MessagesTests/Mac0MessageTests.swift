import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct Mac0MessageTests {
    
    // MARK: - Initialization Tests
    
    @Test func testInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A128GCM(),
            IV(): Data([0x05, 0x06, 0x07, 0x08])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/cbor"
        ]
        
        let payload = Data("Mac0 Payload".utf8)
        let externalAAD = Data("Mac0 AAD".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 32))
        
        let mac0Message = Mac0Message(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: symmetricKey
        )
        
        #expect(mac0Message.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(mac0Message.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(mac0Message.payload == payload, "Payload should match the initialized value.")
        #expect(mac0Message.externalAAD == externalAAD, "External AAD should match the initialized value.")
        #expect(mac0Message.key === symmetricKey, "Key should match the initialized key.")
    }
    
    @Test func testEmptyInitialization() async throws {
        let mac0Message = Mac0Message()
        
        #expect(mac0Message.phdr.isEmpty, "Protected header should be empty by default.")
        #expect(mac0Message.uhdr.isEmpty, "Unprotected header should be empty by default.")
        #expect(mac0Message.payload == Data(), "Payload should initialize as empty Data.")
        #expect(mac0Message.externalAAD == Data(), "External AAD should initialize as empty Data.")
        #expect(mac0Message.key == nil, "Key should be nil by default.")
        #expect(mac0Message.authTag == Data(), "AuthTag should initialize as empty Data.")
    }
    
    // MARK: - From Cose Object Tests
    
    @Test func testFromCoseObject() async throws {
        
        let payload = Data("Mac0 Payload".utf8)
        let authTag = Data([0x01, 0x02, 0x03])
        
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A256GCM().identifier!,
            IV(): Data([0x05, 0x06, 0x07, 0x08])
        ]
        let protectedHdrMap = CBOR.map(phdr.mapKeysToCbor)
        let encoded = try CBORSerialization.data(from: protectedHdrMap)
        
        let coseArray: [CBOR] = [
            CBOR.byteString(encoded),
            CBOR.map([
                CBOR.simple(1): CBOR(Direct().identifier!), // Algorithm
                CBOR.simple(5): CBOR(Data([0x05, 0x06, 0x07, 0x08])) // IV
            ]),
            CBOR.byteString(payload),
            CBOR.byteString(authTag)
        ]
        
        let mac0Base = try Mac0Message.fromCoseObject(coseObj: coseArray)
        
        #expect(mac0Base.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(mac0Base.uhdr.count == 2, "Unprotected header should contain 2 attributes.")
        #expect(
            mac0Base.payload == payload,
            "Payload should match the initialized value."
        )
    }
    
    // MARK: - Encode Tests
    
    @Test func testEncode() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): AESMAC12864(),
            IV(): Data([0x09, 0x0A, 0x0B, 0x0C])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]
        
        let payload = Data("Mac0 Encoding Test".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 32))
        
        let mac0Message = Mac0Message(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: symmetricKey
        )
        
        let encoded = try mac0Message.encode()
        let decoded = try CBORSerialization.cbor(from: encoded)
        
        #expect(decoded != nil, "Encoded CBOR should not be nil.")
        
        if case let .tagged(tag, value) = decoded {
            #expect(Int(tag) == mac0Message.cborTag, "CBOR tag should match Mac0 tag.")
            #expect(value.arrayValue!.count == 4, "Encoded CBOR should contain four elements.")
        } else {
            Issue.record("Failed to decode CBOR value.")
        }
    }
    
    // MARK: - Invalid Object Test
    
    @Test func testInvalidCoseObject() async throws {
        let invalidCoseArray: [CBOR] = [
            CBOR.map([
                CBOR.simple(1): CBOR(A128GCM().identifier!)  // Algorithm
            ])
        ]
        
        #expect(throws: CoseError.self) {
            let _ = try Mac0Message.fromCoseObject(coseObj: invalidCoseArray)
        }
    }
}
