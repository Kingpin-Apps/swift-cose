import Testing
import Foundation
import PotentCBOR
import OrderedCollections
@testable import SwiftCOSE

struct Sign1MessageTests {
    
    // MARK: - Initialization Tests
    
    @Test func testInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): Es256(),
            IV(): Data([0x01, 0x02, 0x03, 0x04])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/cbor"
        ]
        
        let payload = Data("Test Payload".utf8)
        let externalAAD = Data("External AAD".utf8)
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        let sign1Message = Sign1Message(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: key
        )
        
        #expect(sign1Message.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(sign1Message.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(sign1Message.payload == payload, "Payload should match the initialized value.")
        #expect(sign1Message.externalAAD == externalAAD, "External AAD should match the initialized value.")
        #expect(sign1Message.key === key, "Key should match the initialized key.")
    }
    
    @Test func testEmptyInitialization() async throws {
        let sign1Message = Sign1Message()
        
        #expect(sign1Message.phdr.isEmpty, "Protected header should be empty by default.")
        #expect(sign1Message.uhdr.isEmpty, "Unprotected header should be empty by default.")
        #expect(sign1Message.payload == Data(), "Payload should initialize as empty Data.")
        #expect(sign1Message.externalAAD == Data(), "External AAD should initialize as empty Data.")
        #expect(sign1Message.key == nil, "Key should be nil by default.")
    }
    
    // MARK: - From Cose Object Tests
    
    @Test func testFromCoseObject() async throws {
        let payload = Data("Test Payload".utf8)
        let signature = Data([0x30, 0x45, 0x02, 0x21])
        
        let phdr: [CoseHeaderAttribute: Any] = [
            Algorithm(): Es256().identifier!
        ]
        let protectedHdrMap = CBOR.map((phdr as Dictionary<AnyHashable, Any>).mapKeysToCbor)
        let encoded = try CBORSerialization.data(from: protectedHdrMap)
        
        let coseArray: CBOR.Array = [
            CBOR.byteString(encoded),
            CBOR.map([CBOR.simple(1): CBOR(Es256().identifier!)]),
            CBOR.byteString(payload),
            CBOR.byteString(signature)
        ]
        
        let sign1Message = try Sign1Message.fromCoseObject(coseObj: coseArray)
        
        #expect(sign1Message.phdr.count == 1, "Protected header should contain 1 attribute.")
        #expect(sign1Message.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(sign1Message.payload == payload, "Payload should match the initialized value.")
        #expect(sign1Message.signature == signature, "Signature should match the provided signature.")
    }
    
    // MARK: - Encode Tests
    
    @Test func testEncode() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): Es256(),
            IV(): Data([0x01, 0x02, 0x03, 0x04])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]
        
        let payload = Data("Encoding Test".utf8)
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        let sign1Message = Sign1Message(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: key
        )
        
        let encoded = try sign1Message.encode()
        
        let decodedMessage = try CoseMessage.decode(
            Sign1Message.self,
            from: encoded
        ) as Sign1Message
        
        let decoded = try CBORSerialization.cbor(from: encoded)
        
        #expect(!decodedMessage.phdr.isEmpty, "Decoded phdr should not be empty.")
        
        if case let .tagged(tag, value) = decoded {
            #expect(tag.rawValue == sign1Message.cborTag, "CBOR tag should match Sign1Message tag.")
            #expect(value.arrayValue!.count == 4, "Encoded CBOR should contain four elements.")
        } else {
            Issue.record("Decoded CBOR should be tagged.")
        }
    }
    
    // MARK: - Signature Structure Tests
    
    @Test func testSignatureStructure() async throws {
        let sign1Message = Sign1Message(
            payload: Data("Signature Test".utf8)
        )
        
        let detachedPayload = Data("Detached Payload".utf8)
        let structure = try sign1Message.createSignatureStructure(detachedPayload: detachedPayload)
        
        #expect(!structure.isEmpty, "Signature structure should not be empty.")
    }
}
