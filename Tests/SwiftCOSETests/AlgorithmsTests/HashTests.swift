import Testing
import Foundation
@testable import SwiftCOSE

struct HashAlgorithmsTests {
    
    @Test func testComputeHashFail() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = HashAlgorithm(
            identifier: .aesCCM_16_64_128,
            fullname: "SHA-1",
            truncSize: 0
        )
        
        #expect(throws: CoseError.self) {
            _ = try hashAlgorithm.computeHash(data: data)
        }
    }
    
    @Test func testSha1() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha1()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3".hexStringToData
        
        #expect(hash == expectedHash, "SHA-1 hash does not match expected value.")
    }
    
    @Test func testSha256() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha256()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = Data([0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08])
        
        #expect(hash == expectedHash, "SHA-256 hash does not match expected value.")
    }
    
    @Test func testSha256Trunc64() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha256Trunc64()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = Data([0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65])
        
        #expect(hash == expectedHash, "SHA-256/64 truncated hash does not match expected value.")
    }
    
    @Test func testSha384() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha384()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9".hexStringToData

        #expect(hash == expectedHash, "SHA-384 hash does not match expected value.")
    }
    
    @Test func testSha512() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha512()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff".hexStringToData

        #expect(hash == expectedHash, "SHA-512 hash does not match expected value.")
    }
    
    @Test func testSha512Trunc64() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha512Trunc64()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = Data([
            0xee, 0x26, 0xb0, 0xdd, 0x4a, 0xf7, 0xe7, 0x49,
            0xaa, 0x1a, 0x8e, 0xe3, 0xc1, 0x0a, 0xe9, 0x92,
            0x3f, 0x61, 0x89, 0x80, 0x77, 0x2e, 0x47, 0x3f,
            0x88, 0x19, 0xa5, 0xd4, 0x94, 0x0e, 0x0d, 0xb2
        ])
        
        #expect(hash == expectedHash, "SHA-512/256 hash does not match expected value.")
        #expect(hash.count == 32, "SHA-512/256 truncated hash length does not match expected value.")
    }
    
    @Test func testShake128() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Shake128()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = "d3b0aa9cd8b7255622cebc631e867d4093d6f6010191a53973c45fec9b07c774".hexStringToData
        
        #expect(hash.count == 256 / 8, "SHAKE-128 hash length does not match expected value.")
        #expect(hash == expectedHash, "SHAKE-128 hash does not match expected value.")
    }
    
    @Test func testShake256() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Shake256()

        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = "b54ff7255705a71ee2925e4a3e30e41aed489a579d5595e0df13e32e1e4dd202a7c7f68b31d6418d9845eb4d757adda6ab189e1bb340db818e5b3bc725d992fa".hexStringToData

        #expect(hash.count == 512 / 8, "SHAKE-256 hash length does not match expected value.")
        #expect(hash == expectedHash, "SHAKE-256 hash does not match expected value.")
    }

    // FIPS-202 reference vector: SHAKE-128 of empty input, truncated to 256 bits.
    @Test func testShake128EmptyInput() async throws {
        let hash = try Shake128().computeHash(data: Data())
        let expectedHash = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26".hexStringToData

        #expect(hash.count == 256 / 8)
        #expect(hash == expectedHash, "SHAKE-128 empty-input hash does not match FIPS-202 reference vector.")
    }

    // FIPS-202 reference vector: SHAKE-256 of empty input, truncated to 512 bits.
    @Test func testShake256EmptyInput() async throws {
        let hash = try Shake256().computeHash(data: Data())
        let expectedHash = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be".hexStringToData

        #expect(hash.count == 512 / 8)
        #expect(hash == expectedHash, "SHAKE-256 empty-input hash does not match FIPS-202 reference vector.")
    }
}
