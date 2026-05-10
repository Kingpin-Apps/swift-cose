import Testing
import Foundation
import PotentCodables
import PotentCBOR
import OrderedCollections
@testable import SwiftCOSE

struct CoseRecipientTests {
    
    // MARK: - Test Initialization
    
    @Test func testRecipientInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): Es256()]
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [ContentType(): "application/cbor"]
        let payload = Data("test payload".utf8)
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        
        let recipient = CoseRecipient(phdr: phdr, uhdr: uhdr, payload: payload, key: key)
        
        #expect(recipient.phdr.count == phdr.count)
        #expect(recipient.uhdr.count == uhdr.count)
        #expect(recipient.payload == payload)
        #expect(recipient.key!.count == key.count)
        #expect(recipient.recipients.isEmpty)
    }
    
    // MARK: - Test Adding Recipients
    
    @Test func testAddingRecipients() async throws {
        let recipient1 = CoseRecipient()
        let recipient2 = CoseRecipient()
        
        recipient1.recipients = [recipient2]
        
        #expect(recipient1.recipients.count == 1)
        #expect(recipient1.recipients.contains { $0 === recipient2 })
    }
    
    // MARK: - Test Hierarchical Recipients
    
    @Test func testHierarchicalRecipients() async throws {
        let parent = CoseRecipient()
        let child1 = CoseRecipient()
        let child2 = CoseRecipient()
        
        parent.recipients = [child1]
        child1.recipients = [child2]
        
        let found = CoseRecipient.hasRecipient(target: child2, in: parent.recipients)
        
        #expect(found == true)
    }
    
    // MARK: - Test Recipient Not Found
    
    @Test func testRecipientNotFound() async throws {
        let parent = CoseRecipient()
        let child = CoseRecipient()
        let unrelated = CoseRecipient()
        
        parent.recipients = [child]
        
        let found = CoseRecipient.hasRecipient(target: unrelated, in: parent.recipients)
        
        #expect(found == false)
    }
    
    // MARK: - Test Create Recipient from CBOR
    
    @Test func testCreateRecipientFromCBOR() async throws {
        let coseArray: CBOR.Array = [
            CBOR.byteString(Data()),  // zero-length Protected header for DIRECT_ENCRYPTION
            CBOR.map([
                CBOR.simple(1): CBOR(Direct().identifier!)
            ]),
            CBOR.byteString(Data())  // zero-length ciphertext for DIRECT_ENCRYPTION
        ]
        
        let recipient: DirectEncryption = try CoseRecipient.createRecipient(recipient: coseArray, context: "testContext")

        #expect(recipient.context == "testContext")
        #expect(recipient.uhdr[Algorithm()] as? CoseAlgorithm == Direct())
    }
    
    // MARK: - Test Create Recipient Error
    
    @Test func testCreateRecipientError() async throws {
        let coseArray: CBOR.Array = [
            CBOR.map([
                CBOR.simple(1): CBOR(Direct().identifier!)
            ]),
        ]
        
        #expect(throws: CoseError.self) {
            let _: DirectEncryption = try CoseRecipient.createRecipient(
                recipient: coseArray,
                context: "testContext"
            )
        }
    }
    
    // MARK: - Test Verify Recipients
    
    @Test func testVerifyRecipients() async throws {
        let keyWrap1 = KeyWrap()
        let keyWrap2 = KeyWrap()
        
        let recipients = [keyWrap1, keyWrap2]
        let result = try CoseRecipient.verifyRecipients(recipients)

        #expect(!result.isEmpty)
        #expect(result.contains("KeyWrap"))
        #expect(result.count == 1)
    }
    
    @Test func testVerifyRecipientsFail() async throws {
        let direct = DirectEncryption()
        let agreement = DirectKeyAgreement()
        let keyWrap = KeyWrap()
        
        let recipients1 = [direct, keyWrap]
        
        let recipients2 = [keyWrap, agreement]
        
        #expect(throws: CoseError.self) {
            _ = try CoseRecipient.verifyRecipients(recipients1)
        }
        
        #expect(throws: CoseError.self) {
            _ = try CoseRecipient.verifyRecipients(recipients2)
        }
    }
    
    
    // MARK: - Test KDFContext
    
    @Test func testGetKDFContextFail() async throws {
        let coseRecipient = CoseRecipient()
        let alg = A128KW()
        
        #expect(throws: CoseError.self) {
            _ = try coseRecipient.getKDFContext(algorithm: alg)
        }
    }
    
    // MARK: - Test KDF Context Creation
    
    @Test func testKDFContextCreation() async throws {
        let algorithm = A128KW()
        let recipient = CoseRecipient()
        
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
    

    // MARK: - Test Ephemeral Key Setup
    
    @Test func testEphemeralKeySetup() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let recipient = CoseRecipient()
        let peerKey = try EC2Key.generateKey(curve: curve)
        
        try recipient.setupEphemeralKey(peerKey: peerKey)
        
        #expect(recipient.key != nil)
        #expect(recipient.uhdr[EphemeralKey()] != nil)
    }
    
    @Test func testEphemeralKeySetupError() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let recipient = CoseRecipient()
        let peerKey = try EC2Key.generateKey(curve: curve)
        
        // Simulate ephemeral key already set
        recipient.uhdrUpdate([EphemeralKey(): peerKey.store])
        
        #expect(throws: CoseError.self) {
            try recipient.setupEphemeralKey(peerKey: peerKey)
        }
    }
}
