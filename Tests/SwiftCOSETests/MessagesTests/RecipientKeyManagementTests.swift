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

    /// rsa-oaep-examples/ps256-128gcm-01.json: A128GCM with an RSA-OAEP-256 recipient.
    @Test func testEncryptRsaOaep256Example() async throws {
        let published = Data(hex: "D8608443A10101A1054C3345EEF78452AAA67EAF7BEF582458B7F6B31FF4C2AC20AB5B2EE5B62D5BDC9A97BDF294E3F804AAD55F71D0986DFC375748818340A201382804581F6D65726961646F632E6272616E64796275636B407273612E6578616D706C6559010071D19F9646F451B7C8F7560303DC62B64F17B50215682AFFEBC79423F2A4350DBB66AAEEF21218E4778F0CF22684A0144758DA5FB662E3B5468D84FFF7519C2A894ACF9C310A3A0F62B311767C935D9D93971F854DE3FF5AE307CE8D004BA1394E14380C6FED081056DB861AF5885659354354889A6006319B33E3055A8B550829662C83D58E5A563C3A4C43FB484672C20EDC16F0A94046B38E4D943C4B4C2A73F6D2EB7C682B2E94FF5AAAFF3007EBDBFB4B6A7204203CC91C1549CE64A7D3792F2FB78B9E6BB2B966EEE060A37DCC03BC4FDAFAE590EF8DC8198C8CCAF9289624F62C79483DD629C38C74FB092F3B383B0CAD3E58C91B21EB3EBE36407808")
        let key = try RSAKey.fromDictionary([
            RSAKpN(): Data(hex: "BC7E29D0DF7E20CC9DC8D509E0F68895922AF0EF452190D402C61B554334A7BF91C9A570240F994FAE1B69035BCFAD4F7E249EB26087C2665E7C958C967B1517413DC3F97A431691A5999B257CC6CD356BAD168D929B8BAE9020750E74CF60F6FD35D6BB3FC93FC28900478694F508B33E7C00E24F90EDF37457FC3E8EFCFD2F42306301A8205AB740515331D5C18F0C64D4A43BE52FC440400F6BFC558A6E32884C2AF56F29E5C52780CEA7285F5C057FC0DFDA232D0ADA681B01495D9D0E32196633588E289E59035FF664F056189F2F10FE05827B796C326E3E748FFA7C589ED273C9C43436CDDB4A6A22523EF8BCB2221615B799966F1ABA5BC84B7A27CF"),
            RSAKpE(): Data(hex: "010001"),
            RSAKpD(): Data(hex: "0969FF04FCC1E1647C20402CF3F736D4CAE33F264C1C6EE3252CFCC77CDEF533D700570AC09A50D7646EDFB1F86A13BCABCF00BD659F27813D08843597271838BC46ED4743FE741D9BC38E0BF36D406981C7B81FCE54861CEBFB85AD23A8B4833C1BEE18C05E4E436A869636980646EECB839E4DAF434C9C6DFBF3A55CE1DB73E4902F89384BD6F9ECD3399FB1ED4B83F28D356C8E619F1F0DC96BBE8B75C1812CA58F360259EAEB1D17130C3C0A2715A99BE49898E871F6088A29570DC2FFA0CEFFFA27F1F055CBAABFD8894E0CC24F176E34EBAD32278A466F8A34A685ACC8207D9EC1FCBBD094996DC73C6305FCA31668BE57B1699D0BB456CC8871BFFBCD"),
            RSAKpP(): Data(hex: "F331593E147FD3A3235675F0D36A06E5426F7C5E78E49B2ACD3E268BA50E48ED2A52F3B4FA492D6BCF70EB3F915A716078A113652E3FA4C6D50AF8606C2D2C28ECAF083B712D6CEE1263C1205DA03BBBFA6F5C2D8B1A96194089CACB306C844A832E2B032B5F96A7EAB6CFE1107299013C8B0E9F089BBABBC504DD8BC138BA4B"),
            RSAKpQ(): Data(hex: "C66B5DDCAB7017E14083F2854F61997F35636C86F2F92B172D2555588EE1ED899BA6B6ADEC0A02024B2E78A91C891256A8571E0EFB3BAC3F41724DE036EC8FA0F93E2CFBDDA59C6FF1816EB3DC938D4E45912423F3F34B7E96C39E2E4D65A3DCD6DFD2B4EF527841001272F77855B6D75D40D54BB65BD1DF8538E96EC4DAD60D"),
            RSAKpDP(): Data(hex: "1F677CFDBE49EF7B7EA1B8A33BB9D260229F20F1562D373864BEA4DD9D97E5A4F2B53991624CB6D7D836DDBA1CBC102E0405D0EA5CF98CFEBC1E298AD20D5749859EE8B23C604053D1FE1DBF5F37C4DEF66D10FB349E5F49AD82DDB435719DF7BD4EE5F107D5D52FA3E8AD9983B538BAE72591E2C98ACAA75ABED1192DFF7457"),
            RSAKpDQ(): Data(hex: "2CCC9F13ACCD9146B57755318E3BBE197FA7642090097C162E86485FC75AF173E965D9C7290D1569092A83E9C2DC9BFC5EE3D490935EE4C41F75BC698C5D1B0CC059AE746B95F1DD408CF5BEBC65C038D4F23153C0C7C4DADF1569C890870B5958568ECF755D8C73389DF1C138353A242414F853B0E7C85A0C4D4E3F4949139D"),
            RSAKpQInv(): Data(hex: "7B6E2406FD03BC75EA22AB94A8D242506A6BBFE36BC8132DBBCE50B8425425062B697AFA180F5685E90E11EB5712D2E6E2B24E2A1E7C75D5940E08301E824470EF38561BE3E9D05F9FCA8E6F69A028A928E85E58212E789BA577B80378D7A995FA6AFEA74BE364661A679F82776C5905F43F7A35692986271E594E1D11F9668D"),
        ])
        
        let decoded = try CoseMessage.decode(EncMessage.self, from: published)
        let recipient = try #require(decoded.recipients.first as? KeyWrap)
        recipient.key = key
        let cek = try #require(try recipient.computeCEK(targetAlgorithm: A128GCM(), ops: "decrypt"))
        #expect(cek.k == Data(hex: "C0FAAD384B2273296F99F784E0B89C3E"))
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
