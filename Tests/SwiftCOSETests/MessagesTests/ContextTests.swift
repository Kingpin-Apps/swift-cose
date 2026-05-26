import Testing
import Foundation
import CBORCodable
@testable import SwiftCOSE

struct ContextTests {
    
    // MARK: - PartyInfo Tests
    
    @Test func testPartyInfo() async throws {
        let partyInfo = PartyInfo(
            identity: Data.randomBytes(count: 32),
            nonce: Data.randomBytes(count: 16),
            other: Data.randomBytes(count: 16)
        )
        let encoded = partyInfo.encode()
        
        #expect(encoded.count == 3, "Encoded PartyInfo should have 3 elements.")
        #expect(
            encoded[0] == CBOR.byteString(partyInfo.identity!),
            "First element should match identity data."
        )
        #expect(encoded[1] == CBOR.byteString(partyInfo.nonce!), "Second element should be empty Data.")
        #expect(encoded[2] == CBOR.byteString(partyInfo.other!), "Third element should be empty Data.")
    }
    
    // MARK: - SuppPubInfo Tests
    
    @Test func testSuppPubInfo() async throws {
        let suppPubInfo = try SuppPubInfo(
            keyDataLength: 16,
            protected: [Algorithm(): EcdhEsHKDF256()],
            other: Data([0x01, 0x02, 0x03])
        )
        let encoded = try suppPubInfo.encode()
        
        #expect(encoded.count == 3, "Encoded SuppPubInfo should have 3 elements.")
        #expect(
            encoded[0] == CBOR
                .unsignedInt(UInt64(suppPubInfo.keyDataLength * 8)),
            "First element should match identity data."
        )
        #expect(
            encoded[1] == CBOR.map(suppPubInfo.protected.mapKeysToCbor),
            "Second element should be empty Data."
        )
        
        let othorCBOR = try! CBORSerialization.cbor(from: suppPubInfo.other)
        #expect(
            encoded[2] == othorCBOR,
            "Third element should be empty Data."
        )
    }
    
    @Test func testSuppPubInfoInvalidKeyLength() async throws {
        #expect(throws: CoseError.self) {
            let _ = try SuppPubInfo(
                keyDataLength: 17,
                protected: [Algorithm(): EcdhEsHKDF256()],
                other: Data([0x01, 0x02, 0x03])
            )
        }
    }
    
    // MARK: - CoseKDFContext Tests
    
    @Test func testCoseKDFContext() async throws {
        let algorithm = A128KW()
        let suppPubInfo = try SuppPubInfo(
            keyDataLength: 16,
            protected: [Algorithm(): EcdhEsHKDF256()],
            other: Data([0x01, 0x02, 0x03])
        )
        let partyUInfo = PartyInfo(
            identity: Data.randomBytes(count: 32),
            nonce: Data.randomBytes(count: 16),
            other: Data.randomBytes(count: 16)
        )
        let partyVInfo = PartyInfo(
            identity: Data.randomBytes(count: 32),
            nonce: Data.randomBytes(count: 16),
            other: Data.randomBytes(count: 16)
        )
        let context = CoseKDFContext(
            algorithm: algorithm,
            suppPubInfo: suppPubInfo,
            partyUInfo: partyUInfo,
            partyVInfo: partyVInfo
        )
        
        let encoded = try context.encode()
        
        let decoded = try CBORSerialization.cbor(from: encoded)
        let decodedArray = decoded.arrayValue
        
        #expect(decodedArray!.count == 4, "Encoded CoseKDFContext should have 4 elements.")
        #expect(
            decodedArray![0] == CBOR(algorithm.identifier!),
            "First element should match algorithm."
        )
        #expect(
            decodedArray![1].arrayValue!.count == 3,
            "Second element should have 3 elements."
        )
        #expect(
            decodedArray![2].arrayValue!.count == 3, "Third element should have 3 elements."
        )
        #expect(
            decodedArray![3].arrayValue!.count == 3, "Fourth element should have 3 elements."
        )
    }
}
