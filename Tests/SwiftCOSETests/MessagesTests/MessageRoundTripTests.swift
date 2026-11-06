import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

/// Known-answer tests against the COSE Working Group examples
/// (https://github.com/cose-wg/Examples), which RFC 9052 and RFC 9053 use.
/// Each test builds the message the example describes, checks that we encode
/// the published bytes, then decodes the published bytes and verifies or
/// decrypts them.
struct CoseWGExampleTests {
    static let plaintext = Data("This is the content.".utf8)
    /// "our-secret", the kid the examples use for symmetric keys.
    static let ourSecret = Data("our-secret".utf8)
    /// hJtXIZ2uSN5kbQfbtTNWbg (16 bytes)
    static let key128 = Data(hex: "849B57219DAE48DE646D07DBB533566E")
    /// hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg (32 bytes)
    static let key256 = Data(hex: "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188")

    static func ed25519Key(withPrivate: Bool) throws -> OKPKey {
        try OKPKey(
            curve: Ed25519Curve(),
            x: Data(hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            d: withPrivate
                ? Data(hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                : nil
        )
    }

    // MARK: - COSE_Encrypt0 (aes-gcm-examples/aes-gcm-enc-01.json)

    @Test func testEncrypt0Example() async throws {
        let expected = Data(hex: "D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A")
        let key = try CoseSymmetricKey(k: Self.key128)

        let msg = Enc0Message(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data(hex: "02D1F7E6F26C43D4868D87CE")],
            payload: Self.plaintext,
            key: key
        )
        #expect(try msg.encode() == expected)

        let decoded = try CoseMessage.decode(Enc0Message.self, from: expected)
        #expect(decoded.phdrEncoded == Data(hex: "A10101"))
        decoded.key = key
        #expect(try decoded.decrypt() == Self.plaintext)
    }

    // MARK: - COSE_Encrypt, direct (aes-gcm-examples/aes-gcm-01.json)

    @Test func testEncryptDirectExample() async throws {
        let expected = Data(hex: "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A20125044A6F75722D73656372657440")
        let key = try CoseSymmetricKey(k: Self.key128)

        let recipient = DirectEncryption(
            uhdr: [Algorithm(): Direct(), KID(): Self.ourSecret]
        )
        let msg = EncMessage(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data(hex: "02D1F7E6F26C43D4868D87CE")],
            payload: Self.plaintext,
            key: key,
            recipients: [recipient]
        )
        #expect(try msg.encode() == expected)

        let decoded = try CoseMessage.decode(EncMessage.self, from: expected)
        #expect(decoded.recipients.count == 1)
        let decodedRecipient = try #require(decoded.recipients.first as? DirectEncryption)
        #expect(decodedRecipient.uhdr[KID()] as? Data == Self.ourSecret)
        decoded.key = key
        #expect(try decoded.decrypt(recipient: decodedRecipient) == Self.plaintext)
    }

    // MARK: - COSE_Encrypt, Partial IV (aes-gcm-examples/aes-gcm-05.json)

    @Test func testEncryptPartialIVExample() async throws {
        let expected = Data(hex: "D8608443A10101A1064261A75824D3D893DFF22BDCF09A58CBBE701371AEE31EE0AA3C1C8A6CE8409D5E5E81A6B5C355A644818340A20125044A6F75722D73656372657440")
        // The full IV is 89F52F65A1C58093000061A7, so the Base IV is the
        // same with the Partial IV (61A7) XORed back out.
        let key = try CoseSymmetricKey(
            k: Self.key128,
            optionalParams: [KpBaseIV(): Data(hex: "89F52F65A1C5809300000000")]
        )

        let msg = EncMessage(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [PartialIV(): Data(hex: "61A7")],
            payload: Self.plaintext,
            key: key,
            recipients: [
                DirectEncryption(uhdr: [Algorithm(): Direct(), KID(): Self.ourSecret])
            ]
        )
        #expect(try msg.encode() == expected)

        let decoded = try CoseMessage.decode(EncMessage.self, from: expected)
        decoded.key = key
        #expect(try decoded.decrypt(recipient: decoded.recipients[0]) == Self.plaintext)
    }

    // MARK: - COSE_Encrypt, AES Key Wrap (aes-wrap-examples/aes-wrap-128-04.json)

    @Test func testEncryptKeyWrapExample() async throws {
        let expected = Data(hex: "D8608443A10101A1054CDDDC08972DF9BE62855291A158246F5556D71834CD1BD3FDCBFFF28CFA0F7D598C138D23B40C225AF5E3F2096A46C766813D818340A20122044A6F75722D7365637265745818112872F405A5AC48A2EDE46AC20E93E3D3A38B9762D0A3E8")
        let cek = Data(hex: "7A1B4CF78F4B8C6E9AB68198C43D22F3")
        let kek = try CoseSymmetricKey(k: Self.key128)

        let recipient = KeyWrap(
            uhdr: [Algorithm(): A128KW(), KID(): Self.ourSecret],
            payload: cek,
            key: kek
        )
        let msg = EncMessage(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data(hex: "DDDC08972DF9BE62855291A1")],
            payload: Self.plaintext,
            recipients: [recipient]
        )
        #expect(try msg.encode() == expected)

        let decoded = try CoseMessage.decode(EncMessage.self, from: expected)
        let decodedRecipient = try #require(decoded.recipients.first as? KeyWrap)
        decodedRecipient.key = kek
        #expect(try decoded.decrypt(recipient: decodedRecipient) == Self.plaintext)
    }

    // MARK: - COSE_Encrypt, ECDH-ES direct (ecdh-direct-examples/p256-hkdf-256-01.json)

    @Test func testEncryptEcdhDirectExample() async throws {
        let published = Data(hex: "D8608443A10101A1054CC9CF4DF2FE6C632BF788641358247ADBE2709CA818FB415F1E5DF66F4E1A51053BA6D65A1A0C52A357DA7A644B8070A151B0818344A1013818A220A40102200121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB0458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540")
        // meriadoc.brandybuck@buckland.example, the static receiver key.
        let receiverKey = try EC2Key(
            curve: P256Curve(),
            x: Data(hex: "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"),
            y: Data(hex: "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"),
            d: Data(hex: "aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")
        )

        let decoded = try CoseMessage.decode(EncMessage.self, from: published)
        let recipient = try #require(decoded.recipients.first as? DirectKeyAgreement)
        #expect(recipient.phdrEncoded == Data(hex: "A1013818"))
        #expect(try recipient.getAttr(EphemeralKey()) is EC2Key)

        recipient.key = receiverKey
        let cek = try #require(try recipient.computeCEK(targetAlgorithm: A128GCM(), ops: "decrypt"))
        #expect(cek.k == Data(hex: "56074D506729CA40C4B4FE50C6439893"))
        #expect(try decoded.decrypt(recipient: recipient) == Self.plaintext)
    }

    // MARK: - COSE_Encrypt, ECDH-ES + A128KW (ecdh-wrap-examples/p256-wrap-128-01.json)

    @Test func testEncryptEcdhKeyWrapExample() async throws {
        let published = Data(hex: "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381CA220A401022001215820ECDBCEC636CC1408A503BBF6B7311B900C9AED9C5B71503848C89A07D0EF6F5B225820D6D1586710C02203E4E53B20DC7B233CA4C8B6853467B9FB8244A3840ACCD6020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818D23BCA11C3F8E35BF6F81412794E159772E946FF4FB31BD1")
        let receiverKey = try EC2Key(
            curve: P256Curve(),
            x: Data(hex: "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"),
            y: Data(hex: "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"),
            d: Data(hex: "aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")
        )

        let decoded = try CoseMessage.decode(EncMessage.self, from: published)
        let recipient = try #require(decoded.recipients.first as? KeyAgreementWithKeyWrap)
        recipient.key = receiverKey
        let cek = try #require(try recipient.computeCEK(targetAlgorithm: A128GCM(), ops: "decrypt"))
        #expect(cek.k == Data(hex: "B2353161740AACF1F7163647984B522A"))
        #expect(try decoded.decrypt(recipient: recipient) == Self.plaintext)
    }

    // MARK: - COSE_Mac0 (hmac-examples/HMac-enc-01.json)

    @Test func testMac0Example() async throws {
        let expected = Data(hex: "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58")
        let key = try CoseSymmetricKey(k: Self.key256)

        let msg = Mac0Message(
            phdr: [Algorithm(): Hmac256()],
            payload: Self.plaintext,
            key: key
        )
        #expect(try msg.macStructure == Data(hex: "84644D41433043A101054054546869732069732074686520636F6E74656E742E"))
        #expect(try msg.encode() == expected)

        let decoded = try CoseMessage.decode(Mac0Message.self, from: expected)
        #expect(decoded.payload == Self.plaintext)
        decoded.key = key
        #expect(try decoded.verifyTag())
    }

    // MARK: - COSE_Mac, direct (hmac-examples/HMac-01.json)

    @Test func testMacDirectExample() async throws {
        let expected = Data(hex: "D8618543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440")
        let key = try CoseSymmetricKey(k: Self.key256)

        let msg = MacMessage(
            phdr: [Algorithm(): Hmac256()],
            payload: Self.plaintext,
            key: key,
            recipients: [
                DirectEncryption(uhdr: [Algorithm(): Direct(), KID(): Self.ourSecret])
            ]
        )
        #expect(try msg.encode() == expected)

        let decoded = try CoseMessage.decode(MacMessage.self, from: expected)
        #expect(decoded.recipients.first is DirectEncryption)
        decoded.key = key
        #expect(try decoded.verifyTag())
    }

    // MARK: - COSE_Sign1 (eddsa-examples/eddsa-sig-01.json)

    @Test func testSign1Example() async throws {
        let expected = Data(hex: "D28445A201270300A10442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA751BF40B58B3BCC32300B1487F3DB34085EEF013BF08F4A44D6FEF0D")

        let msg = Sign1Message(
            phdr: [Algorithm(): EdDSAAlgorithm(), ContentType(): 0],
            uhdr: [KID(): Data("11".utf8)],
            payload: Self.plaintext,
            key: try Self.ed25519Key(withPrivate: true)
        )
        #expect(try msg.createSignatureStructure() == Data(hex: "846A5369676E61747572653145A2012703004054546869732069732074686520636F6E74656E742E"))

        // Ed25519 signing may be hedged with randomness, so compare
        // everything up to the 64-byte signature that ends the message,
        // then check the published signature is re-emitted unchanged.
        let encoded = try msg.encode()
        #expect(encoded.count == expected.count)
        #expect(encoded.dropLast(64) == expected.dropLast(64))
        msg.signature = expected.suffix(64)
        #expect(try msg.encode(sign: false) == expected)

        let decoded = try CoseMessage.decode(Sign1Message.self, from: expected)
        decoded.key = try Self.ed25519Key(withPrivate: false)
        #expect(try decoded.verifySignature())

        // Our own signature verifies too.
        let ours = try CoseMessage.decode(Sign1Message.self, from: encoded)
        ours.key = try Self.ed25519Key(withPrivate: false)
        #expect(try ours.verifySignature())
    }

    // MARK: - COSE_Sign (eddsa-examples/eddsa-01.json)

    @Test func testSignExample() async throws {
        let expected = Data(hex: "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10127A104423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B83557652264E69690DBC1172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106")

        let signer = CoseSignature(
            phdr: [Algorithm(): EdDSAAlgorithm()],
            uhdr: [KID(): Data("11".utf8)],
            key: try Self.ed25519Key(withPrivate: true)
        )
        let msg = SignMessage(
            phdr: [ContentType(): 0],
            payload: Self.plaintext,
            signers: [signer]
        )
        #expect(try signer.createSignatureStructure() == Data(hex: "85695369676E617475726543A1030043A101274054546869732069732074686520636F6E74656E742E"))

        let encoded = try msg.encode()
        #expect(encoded.count == expected.count)
        #expect(encoded.dropLast(64) == expected.dropLast(64))

        let decoded = try CoseMessage.decode(SignMessage.self, from: expected)
        #expect(decoded.signers.count == 1)
        let decodedSigner = decoded.signers[0]
        decodedSigner.key = try Self.ed25519Key(withPrivate: false)
        #expect(try decodedSigner.verifySignature())

        let ours = try CoseMessage.decode(SignMessage.self, from: encoded)
        ours.signers[0].key = try Self.ed25519Key(withPrivate: false)
        #expect(try ours.signers[0].verifySignature())
    }
}

/// Encode → `CoseMessage.decode` → verify / decrypt / verifyTag for every
/// message type, with fresh keys.
struct MessageRoundTripTests {
    static let payload = Data("round trip payload".utf8)
    static let aad = Data("external aad".utf8)

    @Test func testSign1RoundTrip() async throws {
        let key = try EC2Key.generateKey(curve: P256Curve())
        let msg = Sign1Message(
            phdr: [Algorithm(): Es256()],
            uhdr: [KID(): Data("signer".utf8)],
            payload: Self.payload,
            externalAAD: Self.aad,
            key: key
        )
        let encoded = try msg.encode()

        let decoded = try #require(try CoseMessage.decode(CoseMessage.self, from: encoded) as? Sign1Message)
        #expect(decoded.payload == Self.payload)
        decoded.key = key
        decoded.externalAAD = Self.aad
        #expect(try decoded.verifySignature())

        decoded.externalAAD = Data("other aad".utf8)
        #expect(try decoded.verifySignature() == false)
    }

    @Test func testSign1DetachedPayloadRoundTrip() async throws {
        let key = try EC2Key.generateKey(curve: P256Curve())
        let msg = Sign1Message(phdr: [Algorithm(): Es256()], key: key)
        let encoded = try msg.encode(detachedPayload: Self.payload)

        // RFC 9052, section 2: a detached payload is sent as nil.
        let cbor = try CBORSerialization.cbor(from: encoded)
        #expect(cbor.taggedValue?.1.arrayValue?[2] == CBOR.null)

        let decoded = try CoseMessage.decode(Sign1Message.self, from: encoded)
        #expect(decoded.payload == nil)
        decoded.key = key
        #expect(try decoded.verifySignature(detachedPayload: Self.payload))
    }

    @Test func testSignRoundTrip() async throws {
        let ecKey = try EC2Key.generateKey(curve: P256Curve())
        let edKey = try OKPKey.generateKey(curve: Ed25519Curve())
        let msg = SignMessage(
            phdr: [ContentType(): "text/plain"],
            payload: Self.payload,
            signers: [
                CoseSignature(phdr: [Algorithm(): Es256()], key: ecKey),
                CoseSignature(phdr: [Algorithm(): EdDSAAlgorithm()], key: edKey),
            ]
        )
        let encoded = try msg.encode()

        let decoded = try #require(try CoseMessage.decode(CoseMessage.self, from: encoded) as? SignMessage)
        #expect(decoded.payload == Self.payload)
        #expect(decoded.signers.count == 2)
        decoded.signers[0].key = ecKey
        decoded.signers[1].key = edKey
        #expect(try decoded.signers[0].verifySignature())
        #expect(try decoded.signers[1].verifySignature())
    }

    @Test func testMac0RoundTrip() async throws {
        let key = try CoseSymmetricKey.generateKey(keyLength: 16)
        let msg = Mac0Message(
            phdr: [Algorithm(): AESMAC12864()],
            payload: Self.payload,
            externalAAD: Self.aad,
            key: key
        )
        let encoded = try msg.encode()

        let decoded = try #require(try CoseMessage.decode(CoseMessage.self, from: encoded) as? Mac0Message)
        #expect(decoded.payload == Self.payload)
        decoded.key = key
        decoded.externalAAD = Self.aad
        #expect(try decoded.verifyTag())

        decoded.payload = Data("tampered".utf8)
        #expect(try decoded.verifyTag() == false)
    }

    @Test func testMacRoundTrip() async throws {
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        let msg = MacMessage(
            phdr: [Algorithm(): Hmac256()],
            payload: Self.payload,
            key: key,
            recipients: [DirectEncryption(uhdr: [Algorithm(): Direct()])]
        )
        let encoded = try msg.encode()

        let decoded = try #require(try CoseMessage.decode(CoseMessage.self, from: encoded) as? MacMessage)
        #expect(decoded.payload == Self.payload)
        #expect(decoded.recipients.count == 1)
        decoded.key = key
        #expect(try decoded.verifyTag())
    }

    @Test func testEnc0RoundTrip() async throws {
        let key = try CoseSymmetricKey.generateKey(keyLength: 16)
        let msg = Enc0Message(
            phdr: [Algorithm(): AESCCM1664128()],
            uhdr: [IV(): Data.randomBytes(count: 13)],
            payload: Self.payload,
            externalAAD: Self.aad,
            key: key
        )
        let encoded = try msg.encode()

        let decoded = try #require(try CoseMessage.decode(CoseMessage.self, from: encoded) as? Enc0Message)
        #expect(decoded.payload != Self.payload, "The payload slot carries ciphertext.")
        decoded.key = key
        decoded.externalAAD = Self.aad
        #expect(try decoded.decrypt() == Self.payload)
    }

    @Test func testEncKeyWrapRoundTrip() async throws {
        let kek = try CoseSymmetricKey.generateKey(keyLength: 32)
        let msg = EncMessage(
            phdr: [Algorithm(): A256GCM()],
            uhdr: [IV(): Data.randomBytes(count: 12)],
            payload: Self.payload,
            recipients: [KeyWrap(uhdr: [Algorithm(): A256KW()], key: kek)]
        )
        let encoded = try msg.encode()

        let decoded = try #require(try CoseMessage.decode(CoseMessage.self, from: encoded) as? EncMessage)
        let recipient = try #require(decoded.recipients.first as? KeyWrap)
        recipient.key = kek
        #expect(try decoded.decrypt(recipient: recipient) == Self.payload)
    }

    @Test func testEncEcdhDirectRoundTrip() async throws {
        let receiverKey = try EC2Key.generateKey(curve: P256Curve())
        let receiverPublic = try EC2Key(
            curve: P256Curve(),
            x: receiverKey.x,
            y: receiverKey.y
        )
        let recipient = DirectKeyAgreement(
            phdr: [Algorithm(): EcdhEsHKDF256()]
        )
        recipient.localAttrs = [StaticKey(): receiverPublic]

        let msg = EncMessage(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data.randomBytes(count: 12)],
            payload: Self.payload,
            recipients: [recipient]
        )
        let encoded = try msg.encode()

        let decoded = try CoseMessage.decode(EncMessage.self, from: encoded)
        let decodedRecipient = try #require(decoded.recipients.first as? DirectKeyAgreement)
        decodedRecipient.key = receiverKey
        #expect(try decoded.decrypt(recipient: decodedRecipient) == Self.payload)
    }

    @Test func testEncEcdhKeyWrapRoundTrip() async throws {
        let receiverKey = try EC2Key.generateKey(curve: P256Curve())
        let receiverPublic = try EC2Key(
            curve: P256Curve(),
            x: receiverKey.x,
            y: receiverKey.y
        )
        let recipient = KeyAgreementWithKeyWrap(
            phdr: [Algorithm(): EcdhEsA128KW()]
        )
        recipient.localAttrs = [StaticKey(): receiverPublic]

        let msg = EncMessage(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data.randomBytes(count: 12)],
            payload: Self.payload,
            recipients: [recipient]
        )
        let encoded = try msg.encode()

        let decoded = try CoseMessage.decode(EncMessage.self, from: encoded)
        let decodedRecipient = try #require(decoded.recipients.first as? KeyAgreementWithKeyWrap)
        decodedRecipient.key = receiverKey
        #expect(try decoded.decrypt(recipient: decodedRecipient) == Self.payload)
    }

    @Test func testDecodeRejectsMismatchedType() async throws {
        let key = try CoseSymmetricKey.generateKey(keyLength: 16)
        let encoded = try Enc0Message(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data.randomBytes(count: 12)],
            payload: Self.payload,
            key: key
        ).encode()

        #expect(throws: CoseError.self) {
            _ = try CoseMessage.decode(Sign1Message.self, from: encoded)
        }
    }

    @Test func testDecodeRejectsUnwrappedProtectedHeader() async throws {
        // The bug this guards against: a protected header written as a bare
        // map instead of a byte string that wraps it.
        let malformed = Data(hex: "D083A10101A1054C02D1F7E6F26C43D4868D87CE40")
        #expect(throws: CoseError.self) {
            _ = try CoseMessage.decode(Enc0Message.self, from: malformed)
        }
    }

    @Test func testPayloadThatIsNotCBOREncodes() async throws {
        // 0xFF on its own is not a CBOR data item; payloads are opaque bytes.
        let key = try CoseSymmetricKey.generateKey(keyLength: 32)
        let msg = Mac0Message(
            phdr: [Algorithm(): Hmac256()],
            payload: Data([0xFF, 0x00, 0x1C]),
            key: key
        )
        let decoded = try CoseMessage.decode(Mac0Message.self, from: try msg.encode())
        #expect(decoded.payload == Data([0xFF, 0x00, 0x1C]))
    }
}
