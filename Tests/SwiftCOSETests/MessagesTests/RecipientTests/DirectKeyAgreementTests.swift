import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct DirectKeyAgreementTests {
    
    // MARK: - Test Initialization
    
    @Test func testDirectKeyAgreementInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): Direct()]
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [ContentType(): "application/cbor"]
        let payload = Data()
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        
        let keyAgreement = DirectKeyAgreement(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: key
        )
        
        #expect(keyAgreement.phdr.count == phdr.count)
        #expect(keyAgreement.uhdr.count == uhdr.count)
        #expect(keyAgreement.payload == payload)
        #expect(keyAgreement.key != nil)
        #expect(keyAgreement.recipients.isEmpty)
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
        
        let recipient = try DirectKeyAgreement.fromCoseObject(coseObj: coseArray, context: "testContext")
        
        #expect(recipient.context == "testContext")
        #expect(recipient.payload!.isEmpty)
        #expect(recipient.phdr.isEmpty)
        #expect(recipient.uhdr[Algorithm()] as? CoseAlgorithm == Direct())
    }
    
    // MARK: - Test Successful KDF Context
    
    @Test func testKDFContextCreation() async throws {
        let algorithm = A128KW()
        let recipient = DirectKeyAgreement()
        
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
    
    // MARK: - Test Missing KDF Context Attributes
    
    @Test func testKDFContextMissingAttributes() async throws {
        let keyAgreement = DirectKeyAgreement()
        let algorithm = A128KW()
        
        #expect(throws: CoseError.self) {
            _ = try keyAgreement.getKDFContext(algorithm: algorithm)
        }
    }
    
    // MARK: - Test Key Agreement with No Key
    
    @Test func testKeyAgreementNoKey() async throws {
        let keyAgreement = DirectKeyAgreement()
        let algorithm = A128KW()
        
        #expect(throws: CoseError.self) {
            _ = try keyAgreement.computeCEK(targetAlgorithm: algorithm, ops: "derive")
        }
    }
    
    // MARK: - Test Key Agreement with Valid Key
    
    @Test func testKeyAgreementWithKey() async throws {
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        let keyAgreement = DirectKeyAgreement(key: key)
        let algorithm = A128KW()
        
        #expect(throws: CoseError.self) {
            _ = try keyAgreement.computeCEK(targetAlgorithm: algorithm, ops: "derive")
        }
    }
    
    // MARK: - Test Encoding Key Agreement
    
    @Test func testKeyAgreementEncoding() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let keyAgreement = DirectKeyAgreement(
            uhdr: [
                Algorithm(): EcdhEsHKDF256(),
            ]
        )
        keyAgreement.localAttrs[StaticKey()] = try EC2Key.generateKey(curve: curve)
        let encoded = try keyAgreement.encode()
        
        #expect(encoded.count == 3)
    }
    
    // MARK: - Test Ephemeral Key Setup
    
    @Test func testEphemeralKeySetup() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let keyAgreement = DirectKeyAgreement()
        let peerKey = try EC2Key.generateKey(curve: curve)
        
        try keyAgreement.setupEphemeralKey(peerKey: peerKey)
        
        #expect(keyAgreement.key != nil)
        #expect(keyAgreement.uhdr[EphemeralKey()] != nil)
    }
    
    @Test func testEphemeralKeySetupError() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let keyAgreement = DirectKeyAgreement()
        let peerKey = try EC2Key.generateKey(curve: curve)
        
        // Simulate ephemeral key already set
        keyAgreement.uhdrUpdate([EphemeralKey(): peerKey.store])
        
        #expect(throws: CoseError.self) {
            try keyAgreement.setupEphemeralKey(peerKey: peerKey)
        }
    }
    
    // MARK: - Test Compute CEK With Key
    
    @Test func testComputeCEKWithKey() async throws {
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): A128KW()]
        let directEncryption = DirectKeyAgreement(uhdr: uhdr, key: key)
        let algorithm = A128KW()
        
        
        #expect(throws: CoseError.self) {
            _ = try directEncryption
                .computeCEK(targetAlgorithm: algorithm, ops: "encrypt")
        }
    }
    
    @Test func testComputeCEKWithKeyEcdhEsHKDF256Alg() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): EcdhEsHKDF256()]
        let directEncryption = DirectKeyAgreement(uhdr: uhdr, key: key)
        let algorithm = A128KW()
        
        directEncryption.localAttrs[StaticKey()] = try EC2Key.generateKey(curve: curve)
        
        // Simulate setting up PartyU and PartyV attributes
        let partyUId = Data("partyU".utf8)
        let partyUNonce = Data("nonceU".utf8)
        let partyUOther = Data("otherU".utf8)
        
        let partyVId = Data("partyV".utf8)
        let partyVNonce = Data("nonceV".utf8)
        let partyVOther = Data("otherV".utf8)
        
        // Set attributes in the recipient
        directEncryption.phdr[PartyUID()] = partyUId
        directEncryption.phdr[PartyUNonce()] = partyUNonce
        directEncryption.phdr[PartyUOther()] = partyUOther
        
        directEncryption.phdr[PartyVID()] = partyVId
        directEncryption.phdr[PartyVNonce()] = partyVNonce
        directEncryption.phdr[PartyVOther()] = partyVOther
        
        // Set SuppPubOther and SuppPrivOther
        let suppPubOther = Data()
        let suppPrivOther = Data()
        
        directEncryption.localAttrs[SuppPubOther()] = suppPubOther
        directEncryption.localAttrs[SuppPrivOther()] = suppPrivOther
        
        let coseSymmetricKey = try directEncryption.computeCEK(
            targetAlgorithm: algorithm,
            ops: "encrypt"
        )
        
        #expect(coseSymmetricKey != nil)
    }
}
