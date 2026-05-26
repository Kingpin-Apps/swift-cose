import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct MacMessageTests {
    
    // MARK: - Initialization Tests
    
    @Test func testInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): AESMAC12864(),
            IV(): Data([0x01, 0x02, 0x03, 0x04])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/cbor"
        ]
        
        let payload = Data("Mac Payload".utf8)
        let externalAAD = Data("Mac AAD".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 32))
        let recipient = CoseRecipient(phdr: nil, uhdr: nil, payload: Data("recipient data".utf8))
        
        let macMessage = MacMessage(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: symmetricKey,
            recipients: [recipient]
        )
        
        #expect(macMessage.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(macMessage.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(macMessage.payload == payload, "Payload should match the initialized value.")
        #expect(macMessage.externalAAD == externalAAD, "External AAD should match the initialized value.")
        #expect(macMessage.key === symmetricKey, "Key should match the initialized key.")
        #expect(macMessage.recipients.count == 1, "Recipients should contain 1 recipient.")
    }
    
    @Test func testEmptyInitialization() async throws {
        let macMessage = MacMessage()
        
        #expect(macMessage.phdr.isEmpty, "Protected header should be empty by default.")
        #expect(macMessage.uhdr.isEmpty, "Unprotected header should be empty by default.")
        #expect(macMessage.payload == Data(), "Payload should initialize as empty Data.")
        #expect(macMessage.externalAAD == Data(), "External AAD should initialize as empty Data.")
        #expect(macMessage.key == nil, "Key should be nil by default.")
        #expect(macMessage.recipients.isEmpty, "Recipients should be empty by default.")
    }
    
    // MARK: - From Cose Object Tests
    
    @Test func testFromCoseObject() async throws {
        let payload = Data("Mac Payload".utf8)
        let authTag = Data([0x10, 0x11, 0x12])
        
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): AESMAC12864().identifier!,
            IV(): Data([0x05, 0x06, 0x07, 0x08])
        ]
        let protectedHdrMap = CBOR.map(phdr.mapKeysToCbor)
        let encoded = try CBORSerialization.data(from: protectedHdrMap)
        
        let recipient: [CBOR] = [
            CBOR.byteString(Data()),  // Zero-length protected header
            CBOR.map([
                CBOR.simple(1): CBOR(Direct().identifier!) // Algorithm
            ]),
            CBOR.byteString(Data())  // Zero-length ciphertext
        ]
        
        let recipients: [CBOR] = [
            CBOR.array(recipient)
        ]
        
        let coseArray: [CBOR] = [
            CBOR.byteString(encoded),
            CBOR.map([
                CBOR.simple(1): CBOR(Direct().identifier!),
                CBOR.simple(5): CBOR(Data([0x05, 0x06, 0x07, 0x08]))
            ]),
            CBOR.byteString(payload),
            CBOR.byteString(authTag),
            CBOR.array(recipients)
        ]
        
        let macMessage = try MacMessage.fromCoseObject(coseObj: coseArray)
        
        #expect(macMessage.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(macMessage.uhdr.count == 2, "Unprotected header should contain 2 attributes.")
        #expect(macMessage.payload == payload, "Payload should match the initialized value.")
        #expect(macMessage.recipients.count == 1, "Recipients should contain 1 recipient.")
    }
    
    // MARK: - Encode Tests
    
    @Test func testEncode() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): AESMAC12864(),
            IV(): Data([0x0D, 0x0E, 0x0F, 0x10])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]
        
        let payload = Data("Encoding Test".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 32))
        let recipient = DirectEncryption(phdr: phdr, uhdr: uhdr, payload: Data("recipient data".utf8))
        
        let macMessage = MacMessage(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: symmetricKey,
            recipients: [recipient]
        )
        
        let encoded = try macMessage.encode()
        let decoded = try CBORSerialization.cbor(from: encoded)
        
        #expect(decoded != nil, "Encoded CBOR should not be nil.")
        
        if case let .tagged(tag, value) = decoded {
            #expect(Int(tag) == macMessage.cborTag, "CBOR tag should match MacMessage tag.")
            #expect(value.arrayValue!.count == 5, "Encoded CBOR should contain five elements (including recipients).")
        } else {
            Issue.record("Decoded CBOR should be tagged.")
        }
    }
}
