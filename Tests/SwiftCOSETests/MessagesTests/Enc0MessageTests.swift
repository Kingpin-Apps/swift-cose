import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct Enc0MessageTests {
    
    // MARK: - Initialization Tests
    
    @Test func testInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A128GCM(),
            IV(): Data([0x01, 0x02, 0x03, 0x04])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/cbor"
        ]
        
        let payload = Data("Enc0 Payload".utf8)
        let externalAAD = Data("Enc0 AAD".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 16))
        
        let enc0Message = Enc0Message(
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
    
    @Test func testEmptyInitialization() async throws {
        let enc0Message = Enc0Message()
        
        #expect(enc0Message.phdr.isEmpty, "Protected header should be empty by default.")
        #expect(enc0Message.uhdr.isEmpty, "Unprotected header should be empty by default.")
        #expect(enc0Message.payload == Data(), "Payload should initialize as empty Data.")
        #expect(enc0Message.externalAAD == Data(), "External AAD should initialize as empty Data.")
        #expect(enc0Message.key == nil, "Key should be nil by default.")
    }
    
    // MARK: - From Cose Object Tests
    
    @Test func testFromCoseObject() async throws {
        let coseArray: [CBOR] = [
            CBOR.byteString(Data()),  // Zero-length protected header
            CBOR.map([
                CBOR.simple(1): CBOR(Direct().identifier!) // Algorithm
            ]),
            CBOR.byteString(Data())  // Zero-length ciphertext
        ]
        
        let coseBase = try Enc0Message.fromCoseObject(coseObj: coseArray)
        
        #expect(coseBase.phdr.isEmpty)
        #expect(coseBase.uhdr[Algorithm()] as? CoseAlgorithm == Direct())
    }
    
    // MARK: - Encode Tests
    
    @Test func testEncode() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A128GCM(),
            IV(): Data([0x11, 0x12, 0x13, 0x14])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]
        
        let payload = Data("Encoding Test".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 16))
        
        let enc0Message = Enc0Message(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: symmetricKey
        )
        
        let encoded = try enc0Message.encode()
        let decoded = try CBORSerialization.cbor(from: encoded)
        
        #expect(decoded != nil, "Encoded CBOR should not be nil.")
        
        // Extract tag
        if case let .tagged(tag, value) = decoded {
            #expect(Int(tag) == enc0Message.cborTag, "CBOR tag should match Encrypt0 tag.")
            #expect(value.arrayValue!.count == 3, "Encoded CBOR should contain three elements.")
        } else {
            Issue.record("Encoded CBOR should be tagged.")
        }
    }
}
