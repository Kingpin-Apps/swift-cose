import Testing
import Foundation
import CryptoKit
import CryptoSwift
@testable import SwiftCOSE

struct RSAKeyTests {
    
    // MARK: - Test RSA Key Initialization
    
    @Test func testRSAKeyInitialization() async throws {
        let keyBits = 1024
        let rsaKey = try RSAKey.generateKey(keyBits: keyBits)
        
        #expect(rsaKey.n != nil)
        #expect(rsaKey.e != nil)
        #expect(rsaKey.d != nil)
        #expect(rsaKey.p != nil)
        #expect(rsaKey.q != nil)
        #expect(rsaKey.dp != nil)
        #expect(rsaKey.dq != nil)
        #expect(rsaKey.qInv != nil)
    }
    
    // MARK: - Test Invalid Key Generation
    
    @Test func testInvalidKeyGeneration() async throws {
        #expect(throws: CoseError.self) {
            _ = try RSAKey.generateKey(keyBits: 1025)  // Invalid, must be divisible by 8
        }
    }
    
    // MARK: - Test Key Operations
    
    @Test func testKeyOperations() async throws {
        let rsaKey = try RSAKey.generateKey(keyBits: 1024)
        
        let signOp = SignOp()
        let verifyOp = VerifyOp()
        
        rsaKey.keyOps = [signOp, verifyOp]
        
        #expect(rsaKey.keyOps.contains { $0 is SignOp })
        #expect(rsaKey.keyOps.contains { $0 is VerifyOp })
    }
    
    // MARK: - Test From Dictionary
    
    @Test func testFromDictionary() async throws {
        let keyBits = 2048
        let rsaKey = try RSAKey.generateKey(keyBits: keyBits)
        
        let keyDict: [AnyHashable: Any] = [
            RSAKpN(): rsaKey.n!,
            RSAKpE(): rsaKey.e!,
            RSAKpD(): rsaKey.d!,
            RSAKpP(): rsaKey.p!,
            RSAKpQ(): rsaKey.q!,
            RSAKpDP(): rsaKey.dp!,
            RSAKpDQ(): rsaKey.dq!,
            RSAKpQInv(): rsaKey.qInv!
        ]
        
        let restoredKey = try RSAKey.fromDictionary(keyDict)
        
        #expect(restoredKey.n == rsaKey.n)
        #expect(restoredKey.e == rsaKey.e)
        #expect(restoredKey.d == rsaKey.d)
        #expect(restoredKey.p == rsaKey.p)
        #expect(restoredKey.q == rsaKey.q)
        #expect(restoredKey.dp == rsaKey.dp)
        #expect(restoredKey.dq == rsaKey.dq)
        #expect(restoredKey.qInv == rsaKey.qInv)
    }
    
    // MARK: - Test Full Round-Trip (generate → sign → toDictionary → fromDictionary → verify)

    @Test func testGenerateSignSerializeReimportVerify() async throws {
        let message = "Round-trip RSA key serialization".data(using: .utf8)!
        let rsaKey = try RSAKey.generateKey(keyBits: 2048)

        let rsaAlg = try RsaAlgorithm.fromId(for: CoseAlgorithmIdentifier.ps256) as! RsaAlgorithm
        let signature = try rsaAlg.sign(key: rsaKey, data: message)

        let keyDict: [AnyHashable: Any] = [
            RSAKpN(): rsaKey.n!,
            RSAKpE(): rsaKey.e!,
            RSAKpD(): rsaKey.d!,
            RSAKpP(): rsaKey.p!,
            RSAKpQ(): rsaKey.q!,
            RSAKpDP(): rsaKey.dp!,
            RSAKpDQ(): rsaKey.dq!,
            RSAKpQInv(): rsaKey.qInv!,
        ]
        let restoredKey = try RSAKey.fromDictionary(keyDict)

        let restoredVerify = try rsaAlg.verify(key: restoredKey, data: message, signature: signature)
        #expect(restoredVerify, "Signature did not verify against re-imported key")

        let restoredSignature = try rsaAlg.sign(key: restoredKey, data: message)
        let originalVerify = try rsaAlg.verify(key: rsaKey, data: message, signature: restoredSignature)
        #expect(originalVerify, "Re-imported key produced a signature that the original failed to verify")
    }

    // MARK: - Test Key Deletion
    
    @Test func testKeyDeletion() async throws {
        let rsaKey = try RSAKey.generateKey(keyBits: 1024)
        
        try rsaKey.delete(key: RSAKpD())
        
        #expect(rsaKey.d == nil)
        #expect(rsaKey.n != nil)
        #expect(rsaKey.e != nil)
    }
    
    // MARK: - Test Description
    
    @Test func testDescription() async throws {
        let rsaKey = try RSAKey.generateKey(keyBits: 1024)
        
        let description = rsaKey.description
        
        #expect(description.contains("COSE_Key"))
        #expect(description.contains("RSAKey"))
    }
}
