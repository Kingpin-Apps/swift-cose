import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

/// COSE_Mac with key wrap and key agreement recipients, ECDH static-static,
/// and RSA-OAEP key wrap. Known-answer tests use the COSE WG examples
/// (https://github.com/cose-wg/Examples).
struct RecipientKeyManagementTests {
    static let plaintext = Data("This is the content.".utf8)
    static let ourSecret = Data("our-secret".utf8)
    static let key128 = Data(hex: "849B57219DAE48DE646D07DBB533566E")

    /// meriadoc.brandybuck@buckland.example, the receiver in the ECDH examples.
    static func receiverKey() throws -> EC2Key {
        try EC2Key(
            curve: P256Curve(),
            x: Data(hex: "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"),
            y: Data(hex: "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"),
            d: Data(hex: "aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")
        )
    }

    static func publicPart(of key: EC2Key) throws -> EC2Key {
        try EC2Key(curve: key.curve, x: key.x, y: key.y)
    }

    static func algorithm(_ id: CoseAlgorithmIdentifier) throws -> CoseAlgorithm {
        try CoseAlgorithm.fromId(for: id)
    }

    // MARK: - COSE_Mac known answers

    /// aes-wrap-examples/aes-wrap-128-01.json: AES-MAC-128/64 with an A128KW recipient.
    @Test func testMacKeyWrapExample() async throws {
        let expected = Data(hex: "D8618543A1010EA054546869732069732074686520636F6E74656E742E4836F5AFAF0BAB5D43818340A20122044A6F75722D73656372657458182F8A3D2AA397D3D5C40AAF9F6656BAFA5DB714EF925B72BC")
        let kek = try CoseSymmetricKey(k: Self.key128)

        let recipient = KeyWrap(
            uhdr: [Algorithm(): A128KW(), KID(): Self.ourSecret],
            payload: Data(hex: "DDDC08972DF9BE62855291A17A1B4CF7"),
            key: kek
        )
        let msg = MacMessage(
            phdr: [Algorithm(): AESMAC12864()],
            payload: Self.plaintext,
            recipients: [recipient]
        )
        #expect(try msg.encode() == expected)

        let decoded = try CoseMessage.decode(MacMessage.self, from: expected)
        let decodedRecipient = try #require(decoded.recipients.first as? KeyWrap)
        decodedRecipient.key = kek
        #expect(try decoded.verifyTag(recipient: decodedRecipient))
    }

    /// ecdh-direct-examples/p256-hkdf-256-03.json: HS512 with an ECDH-ES recipient.
    @Test func testMacEcdhDirectExample() async throws {
        let published = Data(hex: "D8618543A10107A054546869732069732074686520636F6E74656E742E5840DB49CF4E1444B976C74D550A6134E1A69774AE0F132AD38FB5F409B25740EE564870FBAEB0EE01BA4A7E7DFD2BBBECBF21E5BB1B7CCD94210375D3461AF851EA818344A1013818A220A40102200121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB0458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540")
        let decoded = try CoseMessage.decode(MacMessage.self, from: published)
        let recipient = try #require(decoded.recipients.first as? DirectKeyAgreement)
        recipient.key = try Self.receiverKey()

        let cek = try #require(try recipient.deriveCEK(targetAlgorithm: Hmac512(), ops: "decrypt"))
        #expect(cek.k == Data(hex: "69220077533E89BDA8DA04814ACCB4703E8C9B009033C8F6A7E65DBB3BCA621B2CF279C6842998CB2B4D2BBAD2E6652824F424D7B7004CC2D6A7384086CF5FF8"))
        #expect(try decoded.verifyTag(recipient: recipient))
    }

    /// ecdh-wrap-examples/p256-wrap-128-03.json: HS512 with an ECDH-ES + A128KW recipient.
    @Test func testMacEcdhKeyWrapExample() async throws {
        let published = Data(hex: "D8618543A10107A054546869732069732074686520636F6E74656E742E584029AE099F8876172256B7823347E3BC0DDB133835297292691884E3BFAD629586AC00D0A24DD44C508B5A92DF6FE711345CD7CBE87257C5D7D0DA03ADA33B2FA7818344A101381CA220A401022001215820E4CFD3201DE9D3A56315FA0AF77105331EF03666C85A5F4BB67C309CB3386067225820A5EE5A8670A96163092B992BD17CAD47866AD8579C4B2676C3B5BB7E01ADD7560458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655848836026593749A7C92049501148814F87FC396856E74739D6B39C99154E690E7FA1BEB86B5669722467EF083E8EF68D09DC674B0D94294597C27DD5016C937DD4056F7B85BE144926")
        let decoded = try CoseMessage.decode(MacMessage.self, from: published)
        let recipient = try #require(decoded.recipients.first as? KeyAgreementWithKeyWrap)
        recipient.key = try Self.receiverKey()
        #expect(try decoded.verifyTag(recipient: recipient))
    }

    // MARK: - ECDH static-static known answers

    /// ecdh-direct-examples/p256-ss-hkdf-256-03.json: HS512 with an ECDH-SS recipient.
    @Test func testMacEcdhStaticStaticExample() async throws {
        let published = Data(hex: "D8618543A10107A054546869732069732074686520636F6E74656E742E5840D0DFD9778CCAA9D7ABEB317FCA2316BB0480DEA2B436B171639693DA334DCCA476A0FF8CD5556DA61E415F4B182F305103375E25C7C9650E917C6CD1E1E5F321818344A101381AA321A42001215820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9CF4DF2FE6C632BF7886413F76E8852271942C33FFD7A1BF85EBE223D0E672B40")
        let decoded = try CoseMessage.decode(MacMessage.self, from: published)
        let recipient = try #require(decoded.recipients.first as? DirectKeyAgreement)
        recipient.key = try Self.receiverKey()
        #expect(try decoded.verifyTag(recipient: recipient))
    }

    /// ecdh-direct-examples/p256-ss-hkdf-256-01.json: A128GCM with an ECDH-SS recipient.
    @Test func testEncryptEcdhStaticStaticExample() async throws {
        let published = Data(hex: "D8608443A10101A1054CD7923E677B71A3F40A179643582455DE918D6CA1E33BEDE48DB6E48678A8159214E76B2099E74AA52F250B940D13C4E7AB78818344A101381AA321A42001215820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9CF4DF2FE6C632BF7886413F76E88523A8260B857D70B350027FD842B5E594740")
        let decoded = try CoseMessage.decode(EncMessage.self, from: published)
        let recipient = try #require(decoded.recipients.first as? DirectKeyAgreement)
        recipient.key = try Self.receiverKey()
        let cek = try #require(try recipient.computeCEK(targetAlgorithm: A128GCM(), ops: "decrypt"))
        #expect(cek.k == Data(hex: "A6C2365CBC7672FBB5DB614B9A223AE3"))
        #expect(try decoded.decrypt(recipient: recipient) == Self.plaintext)
    }

    // MARK: - COSE_Mac round trips

    @Test func testMacKeyWrapRoundTrip() async throws {
        let kek = try CoseSymmetricKey.generateKey(keyLength: 16)
        let msg = MacMessage(
            phdr: [Algorithm(): Hmac256()],
            payload: Self.plaintext,
            recipients: [KeyWrap(uhdr: [Algorithm(): A128KW()], key: kek)]
        )
        let encoded = try msg.encode()

        let decoded = try CoseMessage.decode(MacMessage.self, from: encoded)
        let recipient = try #require(decoded.recipients.first as? KeyWrap)
        recipient.key = kek
        #expect(try decoded.verifyTag(recipient: recipient))

        recipient.key = try CoseSymmetricKey.generateKey(keyLength: 16)
        #expect(throws: (any Error).self) {
            _ = try decoded.verifyTag(recipient: recipient)
        }
    }

    @Test("COSE_Mac with ECDH recipients round-trips", arguments: [
        CoseAlgorithmIdentifier.ecdhES_HKDF_256,
        .ecdhES_HKDF_512,
        .ecdhSS_HKDF_256,
        .ecdhSS_HKDF_512,
        .ecdhES_A128KW,
        .ecdhES_A256KW,
        .ecdhSS_A128KW,
        .ecdhSS_A256KW,
    ])
    func testMacEcdhRoundTrip(_ id: CoseAlgorithmIdentifier) async throws {
        let receiver = try EC2Key.generateKey(curve: P256Curve())
        let recipient = try Self.ecdhRecipient(id, receiver: receiver)

        let msg = MacMessage(
            phdr: [Algorithm(): Hmac256()],
            payload: Self.plaintext,
            recipients: [recipient]
        )
        let encoded = try msg.encode()

        let decoded = try CoseMessage.decode(MacMessage.self, from: encoded)
        let decodedRecipient = try #require(decoded.recipients.first)
        decodedRecipient.key = receiver
        #expect(try decoded.verifyTag(recipient: decodedRecipient))
    }

    // MARK: - COSE_Encrypt round trips

    @Test("COSE_Encrypt with ECDH-SS recipients round-trips", arguments: [
        CoseAlgorithmIdentifier.ecdhSS_HKDF_256,
        .ecdhSS_HKDF_512,
        .ecdhSS_A128KW,
        .ecdhSS_A192KW,
    ])
    func testEncEcdhStaticStaticRoundTrip(_ id: CoseAlgorithmIdentifier) async throws {
        let receiver = try EC2Key.generateKey(curve: P256Curve())
        let recipient = try Self.ecdhRecipient(id, receiver: receiver)

        let msg = EncMessage(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data.randomBytes(count: 12)],
            payload: Self.plaintext,
            recipients: [recipient]
        )
        let encoded = try msg.encode()

        let decoded = try CoseMessage.decode(EncMessage.self, from: encoded)
        let decodedRecipient = try #require(decoded.recipients.first)
        // The sender's static public key travels in the header.
        #expect((try? decodedRecipient.getAttr(StaticKey())) is EC2Key)
        decodedRecipient.key = receiver
        #expect(try decoded.decrypt(recipient: decodedRecipient) == Self.plaintext)
    }

    @Test func testEncRsaOaepKeyWrapRoundTrip() async throws {
        let rsaKey = try RSAKey.generateKey(keyBits: 2048)
        let msg = EncMessage(
            phdr: [Algorithm(): A256GCM()],
            uhdr: [IV(): Data.randomBytes(count: 12)],
            payload: Self.plaintext,
            recipients: [KeyWrap(uhdr: [Algorithm(): RsaesOaepSha256()], key: rsaKey)]
        )
        let encoded = try msg.encode()

        let decoded = try CoseMessage.decode(EncMessage.self, from: encoded)
        let recipient = try #require(decoded.recipients.first as? KeyWrap)
        recipient.key = rsaKey
        #expect(try decoded.decrypt(recipient: recipient) == Self.plaintext)
    }

    // MARK: - Helpers

    /// An ECDH recipient for `receiver`. Static-static algorithms get a
    /// static sender key; ephemeral ones generate their own.
    static func ecdhRecipient(_ id: CoseAlgorithmIdentifier, receiver: EC2Key) throws -> CoseRecipient {
        let alg = try algorithm(id)
        let recipient: CoseRecipient
        switch id {
            case .ecdhES_HKDF_256, .ecdhES_HKDF_512, .ecdhSS_HKDF_256, .ecdhSS_HKDF_512:
                recipient = DirectKeyAgreement(phdr: [Algorithm(): alg])
            default:
                recipient = KeyAgreementWithKeyWrap(phdr: [Algorithm(): alg])
        }
        recipient.localAttrs = [StaticKey(): try publicPart(of: receiver)]
        if [.ecdhSS_HKDF_256, .ecdhSS_HKDF_512, .ecdhSS_A128KW, .ecdhSS_A192KW, .ecdhSS_A256KW].contains(id) {
            recipient.key = try EC2Key.generateKey(curve: P256Curve())
        }
        return recipient
    }
}
