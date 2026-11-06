import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

/// Decoding takes bytes from the network, so malformed input must throw, never
/// trap. These tests feed broken headers, broken CBOR and mutated copies of the
/// COSE WG examples through decode (and verify / decrypt where a message
/// survives decoding).
struct MalformedInputTests {
    static let key128 = Data(hex: "849B57219DAE48DE646D07DBB533566E")
    static let key256 = Data(hex: "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188")

    /// The published examples from `CoseWGExampleTests`.
    static let examples: [String] = [
        // Encrypt0, aes-gcm-enc-01
        "D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A",
        // Encrypt, direct, aes-gcm-01
        "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A20125044A6F75722D73656372657440",
        // Encrypt, ECDH-ES, p256-hkdf-256-01
        "D8608443A10101A1054CC9CF4DF2FE6C632BF788641358247ADBE2709CA818FB415F1E5DF66F4E1A51053BA6D65A1A0C52A357DA7A644B8070A151B0818344A1013818A220A40102200121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB0458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        // Encrypt, A128KW, aes-wrap-128-04
        "D8608443A10101A1054CDDDC08972DF9BE62855291A158246F5556D71834CD1BD3FDCBFFF28CFA0F7D598C138D23B40C225AF5E3F2096A46C766813D818340A20122044A6F75722D7365637265745818112872F405A5AC48A2EDE46AC20E93E3D3A38B9762D0A3E8",
        // Encrypt, ECDH-ES + A128KW, p256-wrap-128-01
        "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381CA220A401022001215820ECDBCEC636CC1408A503BBF6B7311B900C9AED9C5B71503848C89A07D0EF6F5B225820D6D1586710C02203E4E53B20DC7B233CA4C8B6853467B9FB8244A3840ACCD6020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818D23BCA11C3F8E35BF6F81412794E159772E946FF4FB31BD1",
        // Mac0, HMac-enc-01
        "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
        // Mac, HMac-01
        "D8618543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440",
        // Sign1, eddsa-sig-01
        "D28445A201270300A10442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA751BF40B58B3BCC32300B1487F3DB34085EEF013BF08F4A44D6FEF0D",
        // Sign, eddsa-01
        "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10127A104423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B83557652264E69690DBC1172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106",
    ]

    /// Decode, then exercise the message with plausible keys. Any outcome is
    /// fine except a crash.
    static func exercise(_ bytes: Data) {
        guard let msg = try? CoseMessage.decode(CoseMessage.self, from: bytes) else { return }
        _ = msg.description
        switch msg {
            case let m as Enc0Message:
                m.key = try? CoseSymmetricKey(k: key128)
                _ = try? m.decrypt()
            case let m as EncMessage:
                m.key = try? CoseSymmetricKey(k: key128)
                for recipient in m.recipients {
                    _ = recipient.description
                    if recipient is KeyWrap {
                        recipient.key = try? CoseSymmetricKey(k: key128)
                    }
                    if recipient is DirectKeyAgreement || recipient is KeyAgreementWithKeyWrap {
                        recipient.key = try? EC2Key.generateKey(curve: P256Curve())
                    }
                    _ = try? m.decrypt(recipient: recipient)
                }
            case let m as Mac0Message:
                m.key = try? CoseSymmetricKey(k: key256)
                _ = try? m.verifyTag()
            case let m as MacMessage:
                m.key = try? CoseSymmetricKey(k: key256)
                _ = try? m.verifyTag()
            case let m as Sign1Message:
                // A key type that may not match the header's algorithm.
                m.key = try? EC2Key.generateKey(curve: P256Curve())
                _ = try? m.verifySignature()
            case let m as SignMessage:
                for signer in m.signers {
                    _ = signer.description
                    signer.key = try? EC2Key.generateKey(curve: P256Curve())
                    _ = try? signer.verifySignature()
                }
            default:
                break
        }
    }

    // MARK: - Fuzz-style sweeps over the published examples

    @Test func testTruncatedExamplesThrow() async throws {
        for hex in Self.examples {
            let bytes = Data(hex: hex)
            for length in 0..<bytes.count {
                #expect(throws: (any Error).self, "prefix of \(length) bytes") {
                    _ = try CoseMessage.decode(CoseMessage.self, from: bytes.prefix(length))
                }
            }
        }
    }

    @Test func testMutatedExamplesNeverCrash() async throws {
        for hex in Self.examples {
            let bytes = Data(hex: hex)
            for index in bytes.indices {
                for replacement: UInt8 in [0x00, 0x01, 0x18, 0x1B, 0x3B, 0x40, 0x5B, 0x60, 0x80, 0x9F, 0xA0, 0xA1, 0xBF, 0xC0, 0xF6, 0xFF] {
                    var mutated = bytes
                    mutated[index] = replacement
                    Self.exercise(mutated)
                }
                var flipped = bytes
                flipped[index] ^= 0xFF
                Self.exercise(flipped)
            }
        }
    }

    @Test func testTrailingBytesThrow() async throws {
        let bytes = Data(hex: Self.examples[0]) + Data([0x00])
        #expect(throws: CoseError.self) {
            _ = try CoseMessage.decode(CoseMessage.self, from: bytes)
        }
    }

    // MARK: - Malformed headers

    /// A COSE_Encrypt0 with the given protected bytes and unprotected header.
    static func encrypt0(protected: Data, unprotected: Data = Data([0xA0])) -> Data {
        var bytes = Data([0xD0, 0x83])
        bytes += try! CBORSerialization.data(from: .byteString(protected))
        bytes += unprotected
        bytes += Data([0x41, 0x00])
        return bytes
    }

    @Test("Malformed protected headers throw", arguments: [
        "A201010101",          // duplicate label 1
        "A2010104420000",      // fine map, then trailing junk byte below
        "81A10101",            // an array, not a map
        "A1410101",            // byte-string label
        "A1E101",              // simple-value label
        "A1F601",              // null label
        "A11BFFFFFFFFFFFFFFFF01", // label too large for Int
        "A13BFFFFFFFFFFFFFFFF01", // negative label too large for Int
        "A10141FF",            // alg as a byte string
        "A1011903E7",          // unknown alg 999
        "A101F6",              // alg null
        "A10501",              // IV as an integer
        "A104A0",              // kid as a map
        "A1",                  // truncated map
        "A2",                  // truncated map
        "BF0101",              // unterminated indefinite map
        "A1015B",              // truncated length
    ])
    func testMalformedProtectedHeaders(_ hex: String) async throws {
        var protected = Data(hex: hex)
        if hex == "A2010104420000" { protected += Data([0x00]) }
        #expect(throws: (any Error).self) {
            _ = try CoseMessage.decode(CoseMessage.self, from: Self.encrypt0(protected: protected))
        }
    }

    @Test("Malformed unprotected headers throw", arguments: [
        "A2050101",            // duplicate label 5 (wire duplicate)
        "A20101F501",          // label 1 then simple(21) label
        "80",                  // an array, not a map
        "40",                  // a byte string
        "A1054201",            // truncated IV
        "A10142FF",            // alg byte string
        "A1206B6E6F742061206B6579", // ephemeral key as text
        "A120A2010101",        // ephemeral key map with duplicate kty
        "A120A1011BFFFFFFFFFFFFFFFF", // ephemeral key with huge kty
        "A120A40102201BFFFFFFFFFFFFFFFF215820000000000000000000000000000000000000000000000000000000000000000122F6", // huge crv, null y
        "A120A40102200121012258200000000000000000000000000000000000000000000000000000000000000000", // x as an integer
    ])
    func testMalformedUnprotectedHeaders(_ hex: String) async throws {
        #expect(throws: (any Error).self) {
            _ = try CoseMessage.decode(
                CoseMessage.self,
                from: Self.encrypt0(protected: Data(), unprotected: Data(hex: hex))
            )
        }
    }

    @Test func testDuplicateHeaderLabelsAcrossIntegerWidths() async throws {
        // 1 written in one byte and again in a wider encoding: distinct CBOR
        // items that name the same label.
        #expect(throws: (any Error).self) {
            _ = try CoseMessage.decode(
                CoseMessage.self,
                from: Self.encrypt0(protected: Data(hex: "A20101180101"))
            )
        }
    }

    @Test func testHugeTagThrows() async throws {
        let bytes = Data(hex: "DBFFFFFFFFFFFFFFFF8340A040")
        #expect(throws: CoseError.self) {
            _ = try CoseMessage.decode(CoseMessage.self, from: bytes)
        }
    }

    @Test func testHugeArrayLengthThrows() async throws {
        let bytes = Data(hex: "D09BFFFFFFFFFFFFFFFF")
        #expect(throws: (any Error).self) {
            _ = try CoseMessage.decode(CoseMessage.self, from: bytes)
        }
    }

    @Test func testDeepNestingThrows() async throws {
        let bytes = Data([0xD0, 0x83, 0x40, 0xA1, 0x01]) + Data(repeating: 0x81, count: 5000) + Data([0x00, 0x40])
        #expect(throws: (any Error).self) {
            _ = try CoseMessage.decode(CoseMessage.self, from: bytes)
        }
    }

    @Test func testUnknownHeaderLabelsAreKeptApart() async throws {
        // Two unknown labels, one integer and one text, must not collide.
        let decoded = try CoseMessage.decode(
            Enc0Message.self,
            from: Self.encrypt0(protected: Data(), unprotected: Data(hex: "A219270F016361626302"))
        )
        #expect(decoded.uhdr.count == 2)
    }

    // MARK: - Header and key type mismatches after decoding

    @Test func testSignatureAlgorithmKeyMismatchThrows() async throws {
        // eddsa-sig-01 names EdDSA; verifying it with an EC2 key must throw.
        let msg = try CoseMessage.decode(Sign1Message.self, from: Data(hex: Self.examples[7]))
        msg.key = try EC2Key.generateKey(curve: P256Curve())
        #expect(throws: CoseError.self) {
            _ = try msg.verifySignature()
        }
    }

    @Test func testCoseKeyDecodeRejectsMalformedMaps() async throws {
        for hex in ["A2010101", "A1F601", "81A10101", "A1010B", "A30102200121F6", "A3010420F622F6"] {
            #expect(throws: (any Error).self, "\(hex)") {
                _ = try CoseKey.decode(Data(hex: hex))
            }
        }
    }
}
