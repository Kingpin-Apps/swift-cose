import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct EncMessageTests {

    // MARK: - Initialization Tests
    
    @Test func testInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A128GCM(),
            IV(): Data([0x01, 0x02, 0x03, 0x04])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/cbor"
        ]
        
        let payload = Data("EncMessage Payload".utf8)
        let externalAAD = Data("EncMessage AAD".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 16))
        let recipient = CoseRecipient(uhdr: [:], payload: Data([0xAA, 0xBB]))

        let encMessage = EncMessage(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: symmetricKey,
            recipients: [recipient]
        )
        
        #expect(encMessage.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(encMessage.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(encMessage.payload == payload, "Payload should match the initialized value.")
        #expect(encMessage.externalAAD == externalAAD, "External AAD should match the initialized value.")
        #expect(encMessage.key === symmetricKey, "Key should match the initialized key.")
        #expect(encMessage.recipients.count == 1, "There should be one recipient.")
    }
    
    @Test func testEmptyInitialization() async throws {
        let encMessage = EncMessage()
        
        #expect(encMessage.phdr.isEmpty, "Protected header should be empty by default.")
        #expect(encMessage.uhdr.isEmpty, "Unprotected header should be empty by default.")
        #expect(encMessage.payload == Data(), "Payload should initialize as empty Data.")
        #expect(encMessage.externalAAD == Data(), "External AAD should initialize as empty Data.")
        #expect(encMessage.key == nil, "Key should be nil by default.")
        #expect(encMessage.recipients.isEmpty, "Recipients should initialize as an empty array.")
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
        let recipient = DirectEncryption(
            phdr: phdr,
            uhdr: uhdr,
            payload: Data([0xAA])
        )

        let encMessage = EncMessage(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: symmetricKey,
            recipients: [recipient]
        )
        
        let encoded = try encMessage.encode()
        let decoded = try CBORSerialization.cbor(from: encoded)

        #expect(decoded != nil, "Encoded CBOR should not be nil.")
        
        // Verify tag and structure
        if case let .tagged(tag, value) = decoded {
            #expect(Int(tag) == encMessage.cborTag, "CBOR tag should match EncMessage tag.")
            #expect(value.arrayValue?.count == 4, "Encoded CBOR should contain four elements (including recipients).")
        }
    }
    
    @Test func testEncodeWithoutRecipients() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A128GCM(),
            IV(): Data([0x11, 0x12, 0x13, 0x14])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]
        
        let payload = Data("Encoding Test".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 16))

        let encMessage = EncMessage(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: symmetricKey,
            recipients: []
        )
        
        #expect(throws: CoseError.self) {
            let _ = try encMessage.encode()
        }
    }
    
    // MARK: - Decryption Tests
    
    @Test func testDecryption() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A128GCM(),
            IV(): Data([0x11, 0x12, 0x13, 0x14])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]
        
        let payload = Data("Encoding Test".utf8)
        let symmetricKey = try CoseSymmetricKey(k: Data.randomBytes(count: 16))
        let recipient = DirectEncryption(
            phdr: phdr,
            uhdr: uhdr,
            payload: Data([0xAA])
        )

        let encMessage = EncMessage(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: symmetricKey,
            recipients: [recipient]
        )
        
        let encrypted = try encMessage.encrypt()
        encMessage.payload = encrypted
        
        let decrypted = try encMessage.decrypt(recipient: recipient)
        #expect(decrypted == payload, "Decrypted payload should match original.")
    }
    
    @Test func testDecryptionFailure() async throws {
        let key = try CoseSymmetricKey(k: Data.randomBytes(count: 16))
        let payload = Data("Decryption Failure".utf8)
        let wrongRecipient = CoseRecipient(uhdr: [:], payload: Data([0xBB]))
        
        let encMessage = EncMessage(payload: payload, key: key)
        
        #expect(throws: CoseError.self) {
            let _ = try encMessage.decrypt(recipient: wrongRecipient)
        }
    }
    
    // MARK: - Recipient Tests
    
    @Test func testAddRecipient() async throws {
        let encMessage = EncMessage()
        let recipient = CoseRecipient(uhdr: [:], payload: Data([0xAA, 0xBB]))

        encMessage.recipients.append(recipient)
        
        #expect(encMessage.recipients.count == 1, "Recipient should be added successfully.")
    }
}
