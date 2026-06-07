import Testing
import Foundation
@testable import SwiftCOSE

struct HeadersTests {
    
    // MARK: - CoseHeaderIdentifier Tests
    
    @Test func testCoseHeaderIdentifierFromFullName() async throws {
        #expect(CoseHeaderIdentifier.fromFullName("ALG") == .algorithm)
        #expect(CoseHeaderIdentifier.fromFullName("IV") == .iv)
        #expect(CoseHeaderIdentifier.fromFullName("KID") == .kid)
        #expect(CoseHeaderIdentifier.fromFullName("UNKNOWN") == nil)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_V_OTHER") == .partyVOther)
        #expect(CoseHeaderIdentifier.fromFullName("RESERVED") == .reserved)
        #expect(CoseHeaderIdentifier.fromFullName("CRITICAL") == .critical)
        #expect(CoseHeaderIdentifier.fromFullName("CONTENT_TYPE") == .contentType)
        #expect(CoseHeaderIdentifier.fromFullName("PARTIAL_IV") == .partialIV)
        #expect(CoseHeaderIdentifier.fromFullName("COUNTER_SIGN") == .counterSignature)
        #expect(CoseHeaderIdentifier.fromFullName("COUNTER_SIGN0") == .counterSignature0)
        #expect(CoseHeaderIdentifier.fromFullName("KID_CONTEXT") == .kidContext)
        #expect(CoseHeaderIdentifier.fromFullName("X5_BAG") == .x5bag)
        #expect(CoseHeaderIdentifier.fromFullName("X5_CHAIN") == .x5chain)
        #expect(CoseHeaderIdentifier.fromFullName("X5_T") == .x5t)
        #expect(CoseHeaderIdentifier.fromFullName("X5_U") == .x5u)
        #expect(CoseHeaderIdentifier.fromFullName("EPHEMERAL_KEY") == .ephemeralKey)
        #expect(CoseHeaderIdentifier.fromFullName("STATIC_KEY") == .staticKey)
        #expect(CoseHeaderIdentifier.fromFullName("STATIC_KEY_ID") == .staticKeyID)
        #expect(CoseHeaderIdentifier.fromFullName("SALT") == .salt)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_U_ID") == .partyUID)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_U_NONCE") == .partyUNonce)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_U_OTHER") == .partyUOther)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_V_ID") == .partyVID)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_V_NONCE") == .partyVNonce)
        #expect(CoseHeaderIdentifier.fromFullName("SUPP_PUB_OTHER") == .suppPubOther)
        #expect(CoseHeaderIdentifier.fromFullName("SUPP_PRIV_OTHER") == .suppPrivOther)
        #expect(CoseHeaderIdentifier.fromFullName("NOT_A_REAL_VALUE") == nil)
    }
    
    @Test func testCoseHeaderIdentifierRawValue() async throws {
        #expect(CoseHeaderIdentifier(rawValue: 0) == .reserved)
        #expect(CoseHeaderIdentifier(rawValue: 1) == .algorithm)
        #expect(CoseHeaderIdentifier(rawValue: 2) == .critical)
        #expect(CoseHeaderIdentifier(rawValue: 3) == .contentType)
        #expect(CoseHeaderIdentifier(rawValue: 4) == .kid)
        #expect(CoseHeaderIdentifier(rawValue: 5) == .iv)
        #expect(CoseHeaderIdentifier(rawValue: 6) == .partialIV)
        #expect(CoseHeaderIdentifier(rawValue: 7) == .counterSignature)
        #expect(CoseHeaderIdentifier(rawValue: 9) == .counterSignature0)
        #expect(CoseHeaderIdentifier(rawValue: 10) == .kidContext)
        #expect(CoseHeaderIdentifier(rawValue: 32) == .x5bag)
        #expect(CoseHeaderIdentifier(rawValue: 33) == .x5chain)
        #expect(CoseHeaderIdentifier(rawValue: 34) == .x5t)
        #expect(CoseHeaderIdentifier(rawValue: 35) == .x5u)
        #expect(CoseHeaderIdentifier(rawValue: -1) == .ephemeralKey)
        #expect(CoseHeaderIdentifier(rawValue: -2) == .staticKey)
        #expect(CoseHeaderIdentifier(rawValue: -3) == .staticKeyID)
        #expect(CoseHeaderIdentifier(rawValue: -20) == .salt)
        #expect(CoseHeaderIdentifier(rawValue: -21) == .partyUID)
        #expect(CoseHeaderIdentifier(rawValue: -22) == .partyUNonce)
        #expect(CoseHeaderIdentifier(rawValue: -23) == .partyUOther)
        #expect(CoseHeaderIdentifier(rawValue: -24) == .partyVID)
        #expect(CoseHeaderIdentifier(rawValue: -25) == .partyVNonce)
        #expect(CoseHeaderIdentifier(rawValue: -26) == .partyVOther)
        #expect(CoseHeaderIdentifier(rawValue: -998) == .suppPubOther)
        #expect(CoseHeaderIdentifier(rawValue: -999) == .suppPrivOther)
        #expect(CoseHeaderIdentifier(rawValue: 99) == nil)  // Test for an invalid value
    }
    
    // MARK: - CoseHeaderAttribute Tests
    
    @Test func testCoseHeaderAttributeFromIdWithBinaryIntegerTypes() async throws {
        // Regression: on swift-corelibs-foundation (Linux/Windows) CBOR decode
        // yields integer header keys as UInt64/Int64, which do not bridge to Int
        // via `as?`. The BinaryInteger case in fromId(for:) must accept them all.
        let kid = KID()

        #expect(try CoseHeaderAttribute.fromId(for: UInt64(4)) == kid)
        #expect(try CoseHeaderAttribute.fromId(for: Int64(4)) == kid)
        #expect(try CoseHeaderAttribute.fromId(for: Int(4)) == kid)
        #expect(try CoseHeaderAttribute.fromId(for: UInt(4)) == kid)
        #expect(try CoseHeaderAttribute.fromId(for: Int32(4)) == kid)

        // Negative identifiers still resolve via signed integer types.
        #expect(try CoseHeaderAttribute.fromId(for: Int64(-1)) == EphemeralKey())
        #expect(try CoseHeaderAttribute.fromId(for: Int(-1)) == EphemeralKey())
    }

    @Test func testCoseHeaderAttributeFromIdFail() async throws {
        #expect(throws: CoseError.self) {
            let _ = try CoseHeaderAttribute.fromId(for: [])
        }
        #expect(throws: CoseError.self) {
            let _ = try CoseHeaderAttribute.fromId(for: 99)
        }
        #expect(throws: CoseError.self) {
            let _ = try CoseHeaderAttribute.fromId(for: "NOT_A_REAL_VALUE")
        }
    }
    
    // MARK: - Individual Header Attribute Tests
    @Test("Test All Cose Headers", arguments: CoseHeaderIdentifier.allCases)
    func testCoseAlgorithm(_ hdrId: CoseHeaderIdentifier) async throws {
        let hdr1 = try CoseHeaderAttribute.fromId(for: hdrId)
        let hdr2 = try CoseHeaderAttribute.fromId(for: hdr1.fullname!)
        let hdr3 = try CoseHeaderAttribute.fromId(for: hdrId.rawValue)
        
        #expect(hdr1 == hdr2)
        #expect(hdr2 == hdr3)
        #expect(hdr1.identifier == hdrId.rawValue)
        #expect(hdr1.identifier == CoseHeaderIdentifier.fromFullName(hdr1.fullname!)?.rawValue)
    }
    
    // MARK: - Utility Function Tests
    
    @Test func testIsBstrFunction() async throws {
        #expect(try isBstr(Data([0x01, 0x02])) as! Data == Data([0x01, 0x02]))
        
        #expect(throws: CoseError.self) {
            try isBstr("")
        }
    }
    
    @Test func testCritIsArrayFunction() async throws {
        #expect(try critIsArray([1, 2]) as! [Int] == [1, 2])
        #expect(try critIsArray(["A", "B"]) as! [String] == ["A", "B"])
        
        #expect(throws: CoseError.self) {
            try critIsArray([])
        }
    }
    
    @Test func testContentTypeIsUIntOrTstrFunction() async throws {
        #expect(try contentTypeIsUIntOrTstr(42) as! Int == 42)
        #expect(try contentTypeIsUIntOrTstr("application/json") as! String == "application/json")
        
        #expect(throws: CoseError.self) {
            try contentTypeIsUIntOrTstr(Data())
        }
    }
}
