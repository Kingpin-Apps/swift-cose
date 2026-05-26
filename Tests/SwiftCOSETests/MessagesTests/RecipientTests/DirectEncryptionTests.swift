import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct DirectEncryptionTests {
    
    // MARK: - Test Initialization
    
    @Test func testDirectEncryptionInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): Direct()]
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [ContentType(): "application/cbor"]
        let payload = Data()
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        
        let directEncryption = DirectEncryption(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: key
        )
        
        #expect(directEncryption.phdr.count == phdr.count)
        #expect(directEncryption.uhdr.count == uhdr.count)
        #expect(directEncryption.payload == payload)
        #expect(directEncryption.key!.count == key.count)
        #expect(directEncryption.recipients.isEmpty)
    }
    
    // MARK: - Test fromCoseObject
    
    @Test func testFromCoseObject() async throws {
        let coseArray: [CBOR] = [
            CBOR.byteString(Data()),  // Zero-length protected header
            CBOR.map([
                CBOR.simple(1): CBOR(Direct().identifier!) // Algorithm
            ]),
            CBOR.byteString(Data())  // Zero-length ciphertext
        ]
        
        let recipient = try DirectEncryption.fromCoseObject(coseObj: coseArray, context: "testContext")
        
        #expect(recipient.context == "testContext")
        #expect(recipient.payload!.isEmpty)
        #expect(recipient.phdr.isEmpty)
        #expect(recipient.uhdr[Algorithm()] as? CoseAlgorithm == Direct())
    }
    
    // MARK: - Test Recipients Not Allowed
    
    @Test func testRecipientsNotAllowed() async throws {
        let recipient1 = DirectEncryption()
        let recipient2 = DirectEncryption()
        
        recipient1.recipients = [recipient2]
        
        #expect(throws: CoseError.self) {
            _ = try recipient1.encode()
        }
    }
    
    // MARK: - Test Protected Header Not Empty (Error Case)
    
    @Test func testNonEmptyProtectedHeader() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): Direct()]
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [:]
        let payload = Data()
        
        let directEncryption = DirectEncryption(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload
        )
        
        #expect(throws: CoseError.self) {
            _ = try directEncryption.encode()
        }
    }
    
    // MARK: - Test Valid Encoding
    
    @Test func testValidEncoding() async throws {
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): Direct()]
        let payload = Data()
        
        let directEncryption = DirectEncryption(
            uhdr: uhdr,
            payload: payload
        )
        
        let encoded = try directEncryption.encode()
        
        #expect(encoded.count == 3)
    }
    
    // MARK: - Test Compute CEK Without Key
    
    @Test func testComputeCEKWithoutKey() async throws {
        let directEncryption = DirectEncryption()
        let algorithm = A128KW()
        
        #expect(throws: CoseError.self) {
            _ = try directEncryption.computeCEK(targetAlgorithm: algorithm)
        }
    }
    
    // MARK: - Test Compute CEK With Key
    
    @Test func testComputeCEKWithKey() async throws {
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): A128KW()]
        let directEncryption = DirectEncryption(uhdr: uhdr, key: key)
        let algorithm = A128KW()
        
        
        #expect(throws: CoseError.self) {
            _ = try directEncryption.computeCEK(targetAlgorithm: algorithm)
        }
    }
    
    @Test func testComputeCEKWithKeyDirectAlg() async throws {
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): Direct()]
        let directEncryption = DirectEncryption(uhdr: uhdr, key: key)
        let algorithm = A128KW()
        
        let coseSymmetricKey = try directEncryption.computeCEK(targetAlgorithm: algorithm)
        
        #expect(coseSymmetricKey == nil)
    }
    
    // MARK: - Test KDF Context Creation
    
    @Test func testKDFContextCreation() async throws {
        let algorithm = A128KW()
        let recipient = DirectEncryption()
        
        // Simulate setting up PartyU and PartyV attributes
        let partyUId = Data("partyU".utf8)
        let partyUNonce = Data("nonceU".utf8)
        let partyUOther = Data("otherU".utf8)
        
        let partyVId = Data("partyV".utf8)
        let partyVNonce = Data("nonceV".utf8)
        let partyVOther = Data("otherV".utf8)
        
        // Set attributes in the recipient
        recipient.phdr[PartyUID()] = partyUId
        recipient.phdr[PartyUNonce()] = partyUNonce
        recipient.phdr[PartyUOther()] = partyUOther
        
        recipient.phdr[PartyVID()] = partyVId
        recipient.phdr[PartyVNonce()] = partyVNonce
        recipient.phdr[PartyVOther()] = partyVOther
        
        // Set SuppPubOther and SuppPrivOther
        let suppPubOther = Data("suppPubOther".utf8)
        let suppPrivOther = Data("suppPrivOther".utf8)
        
        recipient.localAttrs[SuppPubOther()] = suppPubOther
        recipient.localAttrs[SuppPrivOther()] = suppPrivOther
        
        // Call getKDFContext
        let kdfContext = try recipient.getKDFContext(algorithm: algorithm)
        
        // Verify the KDF Context Fields
        #expect(kdfContext.algorithm == algorithm)
        #expect(kdfContext.partyUInfo.identity == partyUId)
        #expect(kdfContext.partyUInfo.nonce == partyUNonce)
        #expect(kdfContext.partyUInfo.other == partyUOther)
        
        #expect(kdfContext.partyVInfo.identity == partyVId)
        #expect(kdfContext.partyVInfo.nonce == partyVNonce)
        #expect(kdfContext.partyVInfo.other == partyVOther)
        
        #expect(kdfContext.suppPubInfo.keyDataLength == algorithm.keyLength)
        #expect(kdfContext.suppPubInfo.other == suppPubOther)
        #expect(kdfContext.suppPrivInfo == suppPrivOther)
    }
}
