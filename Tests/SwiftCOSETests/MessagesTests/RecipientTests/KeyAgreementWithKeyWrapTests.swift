import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct KeyAgreementWithKeyWrapTests {

    // MARK: - Test Initialization
    
    @Test func testKeyAgreementWithKeyWrapInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): EcdhEsHKDF256()]
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [ContentType(): "application/cbor"]
        let payload = Data("encryptedCEK".utf8)
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)

        let recipient = KeyAgreementWithKeyWrap(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: key
        )
        
        #expect(recipient.phdr.count == phdr.count)
        #expect(recipient.uhdr.count == uhdr.count)
        #expect(recipient.payload == payload)
        #expect(recipient.key != nil)
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
        
        let recipient = try KeyAgreementWithKeyWrap.fromCoseObject(coseObj: coseArray, context: "testContext")
        
        #expect(recipient.context == "testContext")
        #expect(recipient.payload!.isEmpty)
        #expect(recipient.phdr.isEmpty)
        #expect(recipient.uhdr[Algorithm()] as? CoseAlgorithm == Direct())
    }
    
    // MARK: - Test CEK Computation (Encrypt)
    
    @Test func testComputeCEKForEncryption() async throws {
        let payload = try CoseSymmetricKey.generateKey(keyLength: 32).k
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        let recipient = KeyAgreementWithKeyWrap(payload: payload, key: key)
        
        let algorithm = A128KW()
        
        let cek = try recipient.computeCEK(targetAlgorithm: algorithm, ops: "encrypt")
        
        #expect(cek != nil)
        #expect(cek!.k == payload)
    }
    
    // MARK: - Test CEK Computation (Decrypt)
    
//    @Test func testComputeCEKForDecryption() async throws {
//        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
//        let payload = try CoseSymmetricKey.generateKey(keyLength: 32).k
//        let key = try EC2Key.generateKey(curve: curve)
//        let recipient = KeyAgreementWithKeyWrap(
//            uhdr: [
//                Algorithm(): EcdhEsA128KW(),
//                EphemeralKey(): try EC2Key.generateKey(curve: curve),
//            ],
//            payload: payload,
//            key: key
//        )
//        
//        let algorithm = A128KW()
//        
//        // Simulate setting up PartyU and PartyV attributes
//        let partyUId = Data()
//        let partyUNonce = Data()
//        let partyUOther = Data()
//        
//        let partyVId = Data()
//        let partyVNonce = Data()
//        let partyVOther = Data()
//        
//        // Set attributes in the recipient
//        recipient.phdr[PartyUID()] = partyUId
//        recipient.phdr[PartyUNonce()] = partyUNonce
//        recipient.phdr[PartyUOther()] = partyUOther
//        
//        recipient.phdr[PartyVID()] = partyVId
//        recipient.phdr[PartyVNonce()] = partyVNonce
//        recipient.phdr[PartyVOther()] = partyVOther
//        
//        // Set SuppPubOther and SuppPrivOther
//        let suppPubOther = Data()
//        let suppPrivOther = Data()
//        
//        recipient.localAttrs[SuppPubOther()] = suppPubOther
//        recipient.localAttrs[SuppPrivOther()] = suppPrivOther
//        
        
//        let computedCEK = try recipient.computeCEK(targetAlgorithm: algorithm, ops: "encrypt")
        
//        recipient.payload = encryptedCEK!.k
//        let decryptedCEK = try recipient.computeCEK(targetAlgorithm: algorithm, ops: "decrypt")
        
//        let recipientDecrypted = KeyAgreementWithKeyWrap(
//            uhdr: [
//                Algorithm(): EcdhEsA128KW(),
//                EphemeralKey(): try EC2Key.generateKey(curve: curve),
//            ],
//            payload: encryptedCEK!.k,
//            key: key
//        )
//        let decryptedDEK = try recipientDecrypted.computeCEK(targetAlgorithm: algorithm, ops: "decrypt")
        
//        #expect(computedCEK != nil)
//        #expect(computedCEK!.k == payload)
//        #expect(decryptedDEK != nil)
//        #expect(decryptedDEK!.k == payload)
//    }
    
    // MARK: - Test Encoding Key Agreement
    
    @Test func testEncodingKeyAgreementWithKeyWrap() async throws {
        let payload = try CoseSymmetricKey.generateKey(keyLength: 32).k
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): EcdhEsA128KW()
        ]
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [ContentType(): "application/cbor"]
        
        let recipient = KeyAgreementWithKeyWrap(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload
        )
        
        recipient.localAttrs[StaticKey()] = try EC2Key.generateKey(curve: curve)
        
        // Simulate setting up PartyU and PartyV attributes
        let partyUId = Data()
        let partyUNonce = Data()
        let partyUOther = Data()
        
        let partyVId = Data()
        let partyVNonce = Data()
        let partyVOther = Data()
        
        // Set attributes in the recipient
        recipient.phdr[PartyUID()] = partyUId
        recipient.phdr[PartyUNonce()] = partyUNonce
        recipient.phdr[PartyUOther()] = partyUOther
        
        recipient.phdr[PartyVID()] = partyVId
        recipient.phdr[PartyVNonce()] = partyVNonce
        recipient.phdr[PartyVOther()] = partyVOther
        
        // Set SuppPubOther and SuppPrivOther
        let suppPubOther = Data()
        let suppPrivOther = Data()
        
        recipient.localAttrs[SuppPubOther()] = suppPubOther
        recipient.localAttrs[SuppPrivOther()] = suppPrivOther
        
        let encoded = try recipient.encode()
        
        #expect(encoded.count == 3)
    }
    
    // MARK: - Test Ephemeral Key Setup
    
    @Test func testEphemeralKeySetup() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let recipient = KeyAgreementWithKeyWrap()
        let peerKey = try EC2Key.generateKey(curve: curve)
        
        try recipient.setupEphemeralKey(peerKey: peerKey)
        
        #expect(recipient.key != nil)
        #expect(recipient.uhdr[EphemeralKey()] != nil)
    }
    
    @Test func testEphemeralKeySetupError() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let recipient = KeyAgreementWithKeyWrap()
        let peerKey = try EC2Key.generateKey(curve: curve)
        
        // Simulate ephemeral key already set
        recipient.uhdrUpdate([EphemeralKey(): peerKey.store])
        
        #expect(throws: CoseError.self) {
            try recipient.setupEphemeralKey(peerKey: peerKey)
        }
    }
    
    // MARK: - Test Decryption with Missing Keys
    
    @Test func testDecryptionFailsWithoutKeys() async throws {
        let payload = Data("encryptedCEK".utf8)
        let recipient = KeyAgreementWithKeyWrap(payload: payload)
        
        let algorithm = A128KW()
        
        #expect(throws: CoseError.self) {
            _ = try recipient.computeCEK(targetAlgorithm: algorithm, ops: "decrypt")
        }
    }
}
