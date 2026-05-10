import Testing
import Foundation
import PotentCBOR
import OrderedCollections
@testable import SwiftCOSE

struct CoseSignatureTests {
    
    // MARK: - Initialization Tests
    
    @Test func testInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): Es256(),
            IV(): Data([0x05, 0x06, 0x07, 0x08])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/cbor"
        ]
        
        let payload = Data("Signature Payload".utf8)
        let externalAAD = Data("External AAD".utf8)
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        let coseSignature = CoseSignature(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: key
        )
        
        #expect(coseSignature.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(coseSignature.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(coseSignature.payload == payload, "Payload should match the initialized value.")
        #expect(coseSignature.externalAAD == externalAAD, "External AAD should match the initialized value.")
        #expect(coseSignature.key === key, "Key should match the initialized key.")
    }
    
    @Test func testEmptyInitialization() async throws {
        let coseSignature = CoseSignature()
        
        #expect(coseSignature.phdr.isEmpty, "Protected header should be empty by default.")
        #expect(coseSignature.uhdr.isEmpty, "Unprotected header should be empty by default.")
        #expect(coseSignature.payload == Data(), "Payload should initialize as empty Data.")
        #expect(coseSignature.externalAAD == Data(), "External AAD should initialize as empty Data.")
        #expect(coseSignature.key == nil, "Key should be nil by default.")
    }
    
    // MARK: - From COSE Object Tests
    
    @Test func testFromCoseObject() async throws {
        let payload = Data("Signature Object Payload".utf8)
        
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): Es256().identifier!
        ]
        let protectedHdrMap = CBOR.map(phdr.mapKeysToCbor)
        let encoded = try CBORSerialization.data(from: protectedHdrMap)
        
        let coseArray: CBOR.Array = [
            CBOR.byteString(encoded),
            CBOR.map([CBOR.simple(1): CBOR(Es256().identifier!)]),
            CBOR.byteString(payload)
        ]
        
        let coseSignature = try CoseSignature.fromCoseObject(coseObj: coseArray)
        
        #expect(coseSignature.phdr.count == 1, "Protected header should contain 1 attribute.")
        #expect(coseSignature.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
    }
    
    // MARK: - Encode Tests
    
    @Test func testEncode() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): Es256(),
            IV(): Data([0x09, 0x0A, 0x0B, 0x0C])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]
        
        let payload = Data("Encode Signature".utf8)
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        let coseSignature = CoseSignature(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: key
        )
        
        let parent = SignMessage(phdr: phdr, uhdr: uhdr, payload: payload)
        coseSignature.parent = parent
        
        let encoded = try coseSignature.encode()

        #expect(!encoded.isEmpty, "Encoded CBOR should not be empty.")
    }
    
    // MARK: - Signature Structure Tests
    
    @Test func testSignatureStructure() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): Es256(),
            IV(): Data([0x09, 0x0A, 0x0B, 0x0C])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]
        
        let payload = Data("Signature Structure Test".utf8)
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        let coseSignature = CoseSignature(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: key
        )
        
        let parent = SignMessage(phdr: phdr, uhdr: uhdr)
        coseSignature.parent = parent
        
        let detachedPayload = Data("Detached Signature Payload".utf8)
        let structure = try coseSignature.createSignatureStructure(detachedPayload: detachedPayload)
        
        #expect(!structure.isEmpty, "Signature structure should not be empty.")
    }
    
    // MARK: - Parent Relationship Tests
    
    @Test func testParentRelationship() async throws {
        let coseSignMessage = CoseSignMessage()
        let coseSignature = CoseSignature()
        
        coseSignature.parent = coseSignMessage
        
        #expect(coseSignature.parent === coseSignMessage, "Parent should be correctly assigned.")
    }
}
