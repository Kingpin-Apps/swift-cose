import Testing
import Foundation
import CryptoSwift
@testable import SwiftCOSE

struct RsaAlgorithmTests {
    
    @Test("Test RSA signing and verification", arguments: zip([
        CoseAlgorithmIdentifier.ps256,
        .ps384,
        .ps512,
        .rsa_PKCS1_SHA1,
        .rsa_PKCS1_SHA256,
        .rsa_PKCS1_SHA384,
        .rsa_PKCS1_SHA512
    ], [2048, 3072, 2048, 2048, 2048, 2048, 4096]))
    func testRsaSignVerify(_ algId: CoseAlgorithmIdentifier, _ keyBits: Int) async throws {
        let message = "Test RSA Sign and Verify".data(using: .utf8)!
        
        // swift-crypto accepts RSA keys of 2048 bits or more
        let rsaKey = try RSAKey.generateKey(keyBits: keyBits)
        
        let rsaAlg = try RsaAlgorithm.fromId(
            for: algId
        ) as! RsaAlgorithm
        
        // Sign message
        let signature = try rsaAlg.sign(key: rsaKey, data: message)
        
        // Verify signature
        let isValid = try rsaAlg.verify(key: rsaKey, data: message, signature: signature)
        
        #expect(
            isValid,
            "RSA signature verification failed"
        )
    }
    
    @Test("Test RSA encryption and decryption with OAEP", arguments: zip([
        CoseAlgorithmIdentifier.rsa_ES_OAEP_SHA1,
        .rsa_ES_OAEP_SHA256,
        .rsa_ES_OAEP_SHA512
    ], [2048, 2048, 3072]))
    func testRsaEncryptDecrypt(_ algId: CoseAlgorithmIdentifier, _ keyBits: Int) async throws {
        let plaintext = "Test RSA Encryption and Decryption".data(using: .utf8)!
        
        // swift-crypto accepts RSA keys of 2048 bits or more
        let rsaKey = try RSAKey.generateKey(keyBits: keyBits)
        
        let rsaAlg = try RsaOaep.fromId(
            for: algId
        ) as! RsaOaep
        
        // Encrypt the data
        let ciphertext = try rsaAlg.keyWrap(key: rsaKey, data: plaintext)
        
        // Decrypt the data
        let decrypted = try rsaAlg.keyUnwrap(key: rsaKey, data: ciphertext)
        
        #expect(
            decrypted == plaintext,
            "RSA decryption failed. Expected \(plaintext), got \(decrypted)"
        )
    }
    
    @Test func testGeneratedKeysHaveTheFullModulus() async throws {
        // Every generated key must have a modulus of exactly the requested
        // size; a 2047-bit modulus is rejected as under 2048 bits.
        for _ in 0..<8 {
            let key = try RSAKey.generateKey(keyBits: 2048)
            #expect(key.modulusBitLength == 2048)
        }
    }
    
    @Test func testKeysUnder2048BitsThrowClearly() async throws {
        #expect(throws: CoseError.self) {
            _ = try RSAKey.generateKey(keyBits: 1024)
        }
        
        // A 1024-bit key from elsewhere imports, but using it throws a
        // CoseError that names the size instead of an opaque CryptoKit error.
        let small = try CryptoSwift.RSA(keySize: 1024)
        let key = try RSAKey.fromCryptographyKey(
            extKey: small,
            optionalParams: [RSAKpP(): toBstr(small.primes!.p), RSAKpQ(): toBstr(small.primes!.q)]
        )
        let message = Data("small key".utf8)
        
        func expectSizeError(_ body: () throws -> Void) {
            do {
                try body()
                Issue.record("Expected a CoseError for a 1024-bit key")
            } catch let error as CoseError {
                #expect("\(error)".contains("2048"), "\(error)")
            } catch {
                Issue.record("Expected a CoseError, got \(error)")
            }
        }
        expectSizeError { _ = try Ps256().sign(key: key, data: message) }
        expectSizeError { _ = try Ps256().verify(key: key, data: message, signature: Data(count: 128)) }
        expectSizeError { _ = try RsaesOaepSha1().keyWrap(key: key, data: Data(count: 16)) }
        expectSizeError { _ = try RsaesOaepSha1().keyUnwrap(key: key, data: Data(count: 128)) }
    }
}
