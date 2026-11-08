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
        // RFC 9053, section 5.2: protected is the serialized header map and
        // other is a byte string.
        #expect(
            encoded[1] == CBOR.byteString(
                try CBORSerialization.data(from: .map(try suppPubInfo.protected.mapKeysToCbor()))
            ),
            "Second element should be the serialized protected header."
        )
        #expect(
            encoded[2] == CBOR.byteString(suppPubInfo.other),
            "Third element should be the other bytes."
        )
    }
    
    @Test func testPartyInfoEncodesAbsentFieldsAsNil() async throws {
        let encoded = PartyInfo().encode()
        #expect(encoded == [CBOR.null, CBOR.null, CBOR.null])
    }
    
    @Test func testSuppPubInfoKeepsReceivedProtectedBytes() async throws {
        let suppPubInfo = try SuppPubInfo(
            keyDataLength: 16,
            protected: [Algorithm(): EcdhEsHKDF256()],
            protectedEncoded: Data(hex: "A1013818")
        )
        #expect(try suppPubInfo.encode()[1] == CBOR.byteString(Data(hex: "A1013818")))
    }
    
    /// COSE WG example ecdh-direct-examples/p256-hkdf-256-01.json, Context_hex.
    @Test func testCoseKDFContextExample() async throws {
        let context = CoseKDFContext(
            algorithm: A128GCM(),
            suppPubInfo: try SuppPubInfo(
                keyDataLength: 16,
                protected: [Algorithm(): EcdhEsHKDF256()]
            )
        )
        #expect(try context.encode() == Data(hex: "840183F6F6F683F6F6F682188044A1013818"))
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
