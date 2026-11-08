import Testing
import Foundation
@testable import SwiftCOSE

struct AesCcmAlgorithmTests {
    
    @Test func testAESCCM1664128() async throws {
        let aesCcm = AESCCM1664128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesCcm.keyLength!
        )
        let iv = "89F52F65A1C580933B5261A72F".hexStringToData
        let plaintext = "This is the content.".data(using: .utf8)!
        let aad = "AAD".data(using: .utf8)!
        
        let encryptedData = try aesCcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesCcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }
    
    @Test func testAESCCM1664256() async throws {
        let aesCcm = AESCCM1664256()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesCcm.keyLength!
        )
        let iv = "1234567890ABCDEF1234567801".hexStringToData  // CCM-16-* takes a 13-byte nonce
        let plaintext = "CCM 256-bit key test.".data(using: .utf8)!
        let aad = "AAD".data(using: .utf8)!
        
        let encryptedData = try aesCcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesCcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }
    
    @Test func testAESCCM6464128() async throws {
        let aesCcm = AESCCM6464128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesCcm.keyLength!
        )
        let iv = "A1B2C3D4E5F607".hexStringToData  // CCM-64-* takes a 7-byte nonce
        let plaintext = "AES CCM 64 64 128 test.".data(using: .utf8)!
        let aad = "AAD6464128".data(using: .utf8)!
        
        let encryptedData = try aesCcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesCcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }

    @Test func testAESCCM6464256() async throws {
        let aesCcm = AESCCM6464256()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesCcm.keyLength!
        )
        let iv = "0011AABBCCDDEE".hexStringToData  // CCM-64-* takes a 7-byte nonce
        let plaintext = "AES CCM 64 64 256 test.".data(using: .utf8)!
        let aad = "AAD6464256".data(using: .utf8)!
        
        let encryptedData = try aesCcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesCcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }

    @Test func testAESCCM16128128() async throws {
        let aesCcm = AESCCM16128128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesCcm.keyLength!
        )
        let iv = "DEADBEEFCAFEBABE1122334401".hexStringToData  // CCM-16-* takes a 13-byte nonce
        let plaintext = "AES CCM 16 128 128 test.".data(using: .utf8)!
        let aad = "AAD16128128".data(using: .utf8)!
        
        let encryptedData = try aesCcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesCcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }

    @Test func testAESCCM16128256() async throws {
        let aesCcm = AESCCM16128256()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesCcm.keyLength!
        )
        let iv = "CAFED00DBEEF00112233445501".hexStringToData  // CCM-16-* takes a 13-byte nonce
        let plaintext = "AES CCM 16 128 256 test.".data(using: .utf8)!
        let aad = "AAD16128256".data(using: .utf8)!
        
        let encryptedData = try aesCcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesCcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }

    @Test func testAESCCM64128128() async throws {
        let aesCcm = AESCCM64128128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesCcm.keyLength!
        )
        let iv = "33445566778899".hexStringToData  // CCM-64-* takes a 7-byte nonce
        let plaintext = "AES CCM 64 128 128 test.".data(using: .utf8)!
        let aad = "AAD64128128".data(using: .utf8)!
        
        let encryptedData = try aesCcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesCcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }

    @Test func testAESCCM64128256() async throws {
        let aesCcm = AESCCM64128256()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesCcm.keyLength!
        )
        let iv = "11223344556677".hexStringToData  // CCM-64-* takes a 7-byte nonce
        let plaintext = "AES CCM 64 128 256 test.".data(using: .utf8)!
        let aad = "AAD64128256".data(using: .utf8)!
        
        let encryptedData = try aesCcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesCcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }
    
    @Test func testAESCCMFailure() async throws {
        let aesCcm = AESCCM1664128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesCcm.keyLength!
        )
        let iv = "".hexStringToData  // Empty IV to induce failure
        let plaintext = "Failure case test".data(using: .utf8)!
        let aad = "FailureAAD".data(using: .utf8)!
        
        #expect(throws: CoseError.self) {
            try aesCcm.encrypt(
                key: key,
                nonce: iv,
                data: plaintext,
                aad: aad
            )
        }
        
        #expect(throws: CoseError.self) {
            try aesCcm.decrypt(
                key: key,
                nonce: iv,
                ciphertext: plaintext,
                aad: aad
            )
        }
    }
}
