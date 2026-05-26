import Testing
import Foundation
import CBORCodable
import OrderedCollections

@testable import SwiftCOSE

struct CoseSignMessageTests {
    
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
        let signers = [CoseSignature(), CoseSignature()]
        
        let coseSignMessage = CoseSignMessage(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            signers: signers
        )
        
        #expect(coseSignMessage.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(coseSignMessage.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(coseSignMessage.payload == payload, "Payload should match the initialized value.")
        #expect(coseSignMessage.signers.count == 2, "There should be two signers.")
        #expect(coseSignMessage.signers.allSatisfy { $0.parent === coseSignMessage }, "All signers should have the parent set to the CoseSignMessage instance.")
    }
    
    @Test func testEmptyInitialization() async throws {
        let coseSignMessage = CoseSignMessage()
        
        #expect(coseSignMessage.phdr.isEmpty, "Protected header should be empty by default.")
        #expect(coseSignMessage.uhdr.isEmpty, "Unprotected header should be empty by default.")
        #expect(coseSignMessage.payload == nil, "Payload should initialize as empty Data.")
        #expect(coseSignMessage.signers.isEmpty, "Signers should initialize as an empty array.")
    }
    
    // MARK: - From COSE Object Tests
    
    @Test func testFromCoseObject() async throws {
        let payload = Data("Test Payload".utf8)
        
        let phdr: [CoseHeaderAttribute: Any] = [
            Algorithm(): Es256().identifier!
        ]
        let protectedHdrMap = CBOR.map((phdr as Dictionary<AnyHashable, Any>).mapKeysToCbor)
        let encoded = try CBORSerialization.data(from: protectedHdrMap)
        
        let signature: [CBOR] = [
            CBOR.byteString(Data()),  // Zero-length protected header
            CBOR.map([
                CBOR.simple(1): CBOR(Es256().identifier!) // Algorithm
            ]),
            CBOR.byteString(Data())  // Zero-length ciphertext
        ]
        
        let signatures: [CBOR] = [
            CBOR.array(signature)
        ]
        
        let coseArray: [CBOR] = [
            CBOR.byteString(encoded),
            CBOR.map([CBOR.simple(1): CBOR(Es256().identifier!)]),
            CBOR.byteString(payload),
            CBOR.array(signatures)
        ]
        
        let coseSignMessage = try CoseSignMessage.fromCoseObject(coseObj: coseArray)
        
        #expect(coseSignMessage.phdr.count == 1, "Protected header should contain 1 attribute.")
        #expect(coseSignMessage.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(coseSignMessage.payload == payload, "Payload should match the initialized value.")
        #expect(coseSignMessage.signers.count == 1, "There should be one signer.")
    }
    
    // MARK: - Encode Tests
    
    @Test func testEncode() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): Es256(),
            IV(): Data([0x05, 0x06, 0x07, 0x08])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]
        
        let payload = Data("Encoding Test".utf8)
        let signer = CoseSignature(
            phdr: phdr,
            uhdr: uhdr,
            key: key
        )
        
        let coseSignMessage = SignMessage(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            signers: [signer]
        )
        
        let encoded = try coseSignMessage.encode()
        let decoded = try CBORSerialization.cbor(from: encoded)
        
        #expect(decoded != nil, "Encoded CBOR should not be nil.")
        
        if case let .tagged(tag, value) = decoded {
            #expect(Int(tag) == coseSignMessage.cborTag, "CBOR tag should match CoseSignMessage tag.")
            #expect(value.arrayValue!.count == 4, "Encoded CBOR should contain four elements.")
        }
    }
    
    // MARK: - Signer Management Tests
    
    @Test func testSignerParentAssignment() async throws {
        let coseSignMessage = CoseSignMessage()
        let signer = CoseSignature()
        
        coseSignMessage.signers = [signer]
        
        #expect(signer.parent === coseSignMessage, "The signer should have the CoseSignMessage set as its parent.")
    }
    
    @Test func testAddingSigners() async throws {
        let coseSignMessage = CoseSignMessage()
        let signer1 = CoseSignature()
        let signer2 = CoseSignature()
        
        coseSignMessage.signers.append(contentsOf: [signer1, signer2])
        
        #expect(coseSignMessage.signers.count == 2, "Two signers should be added to the message.")
        #expect(coseSignMessage.signers.allSatisfy { $0.parent === coseSignMessage }, "All signers should have the parent set.")
    }
}
