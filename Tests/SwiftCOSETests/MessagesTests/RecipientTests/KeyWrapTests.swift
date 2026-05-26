import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct KeyWrapTests {

    // MARK: - Test Initialization
    
    @Test func testKeyWrapInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): A128KW()]
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [ContentType(): "application/cbor"]
        let payload = Data("wrappedCEK".utf8)
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)

        let recipient = KeyWrap(
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
                CBOR.simple(1): CBOR(A128KW().identifier!) // Algorithm
            ]),
            CBOR.byteString(Data())  // Zero-length ciphertext
        ]
        
        let recipient = try KeyWrap.fromCoseObject(coseObj: coseArray, context: "testContext")
        
        #expect(recipient.context == "testContext")
        #expect(recipient.payload!.isEmpty)
        #expect(recipient.phdr.isEmpty)
        #expect(recipient.uhdr[Algorithm()] as? CoseAlgorithm == A128KW())
    }
    
    // MARK: - Test CEK Computation (Encrypt)
    
    @Test func testComputeCEKForEncryption() async throws {
        let payload = try CoseSymmetricKey.generateKey(keyLength: 32).k
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        let recipient = KeyWrap(payload: payload, key: key)
        
        let algorithm = A128KW()
        
        let cek = try recipient.computeCEK(targetAlgorithm: algorithm, ops: "encrypt")
        
        #expect(cek != nil)
        #expect(cek!.k == payload)
    }
    
    // MARK: - Test CEK Computation (Decrypt)
    
//    @Test func testComputeCEKForDecryption() async throws {
//        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
//        let payload = key.k
//        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
//            Algorithm(): A256KW()
//        ]
//        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [ContentType(): "application/cbor"]
//        
//        let recipient = KeyWrap(
//            phdr: phdr,
//            uhdr: uhdr,
//            payload: payload,
//            key: key
//        )
//        
//        let algorithm = A256KW()
//        
//        recipient.payload = payload
//        let decryptedCEK = try recipient.computeCEK(targetAlgorithm: algorithm, ops: "decrypt")
//        
//        #expect(decryptedCEK != nil)
//        #expect(decryptedCEK!.k == payload)
//    }
    
    // MARK: - Test Encoding
    
    @Test func testEncodingKeyWrap() async throws {
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        let payload = key.k
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A256KW()
        ]
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [ContentType(): "application/cbor"]
        
        let recipient = KeyWrap(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            key: key
        )
        
        let encoded = try recipient.encode(targetAlgorithm: A256KW())
        
        #expect(encoded.count == 3)
    }
    
    // MARK: - Test Encryption and Decryption
    
//    @Test func testEncryptAndDecrypt() async throws {
//        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
//        let payload = Data("confidential".utf8)
//        
//        let recipient = KeyWrap(key: key)
//        recipient.payload = payload
//        
//        let algorithm = A256KW()
//        
//        let encryptedPayload = try recipient.encrypt(targetAlgorithm: algorithm)
//        recipient.payload = encryptedPayload
//        
//        let decryptedPayload = try recipient.decrypt(targetAlgorithm: algorithm)
//        
//        #expect(decryptedPayload == payload)
//    }
    
    // MARK: - Test Decryption with Invalid Key
    
    @Test func testDecryptionFailsWithoutValidKey() async throws {
        let payload = Data("wrappedCEK".utf8)
        let recipient = KeyWrap(payload: payload)
        
        let algorithm = A128KW()
        
        #expect(throws: CoseError.self) {
            _ = try recipient.computeCEK(targetAlgorithm: algorithm, ops: "decrypt")
        }
    }
}
