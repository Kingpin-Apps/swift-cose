import Foundation
import PotentCBOR
import OrderedCollections
import Testing

@testable import SwiftCOSE

struct CoseMessageIdentifierTests {

    // MARK: - CoseMessageIdentifier Initialization Tests

    @Test func testCoseMessageIdentifierRawValue() async throws {
        #expect(CoseMessageIdentifier(rawValue: 16) == .encrypt0)
        #expect(CoseMessageIdentifier(rawValue: 96) == .encrypt)
        #expect(CoseMessageIdentifier(rawValue: 17) == .mac0)
        #expect(CoseMessageIdentifier(rawValue: 97) == .mac)
        #expect(CoseMessageIdentifier(rawValue: 18) == .sign1)
        #expect(CoseMessageIdentifier(rawValue: 98) == .sign)
        #expect(CoseMessageIdentifier(rawValue: 99) == nil)  // Invalid value
    }

    // MARK: - Full Name Conversion Tests

    @Test func testCoseMessageIdentifierFromFullName() async throws {
        #expect(CoseMessageIdentifier.fromFullName("COSE_Encrypt0") == .encrypt0)
        #expect(CoseMessageIdentifier.fromFullName("COSE_Encrypt") == .encrypt)
        #expect(CoseMessageIdentifier.fromFullName("COSE_Mac0") == .mac0)
        #expect(CoseMessageIdentifier.fromFullName("COSE_Mac") == .mac)
        #expect(CoseMessageIdentifier.fromFullName("COSE_Sign1") == .sign1)
        #expect(CoseMessageIdentifier.fromFullName("COSE_Sign") == .sign)
        #expect(CoseMessageIdentifier.fromFullName("UNKNOWN") == nil)  // Invalid name
    }
}

struct CoseMessageTests {

    // MARK: - Individual CoseMessage Tests
    @Test("Test All Cose Message", arguments: CoseMessageIdentifier.allCases)
    func testCoseMessage(_ msgId: CoseMessageIdentifier) async throws {
        let msg = try CoseMessage.fromId(for: msgId)
        let expected = CoseMessage.getInstance(for: msgId)
        #expect(msg == expected, "\(msgId) should resolve to \(expected)")
    }

    // MARK: - Initialization Tests

    @Test func testCoseMessageInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A128GCM(),
            IV(): Data([0x01, 0x02, 0x03, 0x04]),
        ]

        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]

        let payload = Data("Test Payload".utf8)
        let externalAAD = Data("AAD Data".utf8)

        let coseMessage = CoseMessage(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD
        )

        #expect(coseMessage.phdr.count == 2, "Protected header should have 2 attributes.")
        #expect(coseMessage.uhdr.count == 1, "Unprotected header should have 1 attribute.")
        #expect(coseMessage.payload == payload, "Payload should match the initialized value.")
        #expect(
            coseMessage.externalAAD == externalAAD,
            "External AAD should match the initialized value.")
    }

    @Test func testEmptyCoseMessageInitialization() async throws {
        let coseMessage = CoseMessage()

        #expect(coseMessage.phdr.isEmpty, "Protected header should be empty.")
        #expect(coseMessage.uhdr.isEmpty, "Unprotected header should be empty.")
        #expect(coseMessage.payload == nil, "Payload should be nil.")
        #expect(coseMessage.externalAAD.isEmpty, "External AAD should be empty.")
    }

    // MARK: - Key Tests

    @Test func testKeyAssignment() async throws {
        let coseMessage = CoseMessage()
        let symmetricKey = try CoseSymmetricKey(
            k: Data.randomBytes(count: 16)
        )

        coseMessage.key = symmetricKey

        #expect(coseMessage.key === symmetricKey, "Key should be correctly assigned.")
    }

    @Test func testDecode() async throws {
        let signedMessage =
            "845869a3012704582060545b786d3a6f903158e35aae9b86548a99bc47d4b0a6f503ab5e78c1a9bbfc6761646472657373583900ddba3ad76313825f4f646f5aa6d323706653bda40ec1ae55582986a463e661768b92deba45b5ada4ab9e7ffd17ed3051b2e03500e0542e9aa166686173686564f452507963617264616e6f20697320636f6f6c2e58403b09cbae8d272ff94befd28cc04b152aea3c1633caffb4924a8a8c45be3ba6332a76d9f2aba833df53803286d32a5ee700990b79a0e86fab3cccdbfd37ce250f"
        let messageData = Data(hex: "D2" + signedMessage)

        let decodedMessage =
            try CoseMessage.decode(
                Sign1Message.self,
                from: messageData
            ) as Sign1Message

        let keyId = decodedMessage.phdr[KID()] as! Data

        let coseKeyDict =
            [
                KpKty(): KtyOKP(),
                OKPKpCurve(): Ed25519Curve(),
                KpKeyOps(): [VerifyOp()],  // Only need verify operation for verification
                OKPKpX(): keyId,
            ] as [AnyHashable: Any]

        let coseKey = try CoseKey.fromDictionary(coseKeyDict)

        decodedMessage.key = coseKey
        let signatureVerified = try decodedMessage.verifySignature()

        #expect(signatureVerified == true, "Signature should be verified.")
    }
}
