import Testing
import Foundation
import X509
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

/// Regression tests for the 2026-11-08 security audit of swift-cose. Each
/// input used to crash the process or be accepted; it must now throw or be
/// refused.
struct AuditRegressionTests {
    static let key128 = Data(hex: "849B57219DAE48DE646D07DBB533566E")
    static let plaintext = Data("This is the content.".utf8)

    static func publicPart(of key: EC2Key) throws -> EC2Key {
        try EC2Key(curve: key.curve, x: key.x, y: key.y)
    }

    // MARK: - CBOR decoding

    @Test("A byte string length near Int.max throws instead of trapping")
    func hugeByteStringLength() throws {
        #expect(throws: (any Error).self) {
            _ = try CoseMessage.decode(CoseMessage.self, from: Data(hex: "5b7fffffffffffffff"))
        }
        #expect(throws: (any Error).self) {
            _ = try CoseMessage.decode(Sign1Message.self, from: Data(hex: "d2845b7fffffffffffffff"))
        }
        #expect(throws: (any Error).self) {
            _ = try CoseKey.decode(Data(hex: "a1015b7fffffffffffffff"))
        }
        #expect(throws: (any Error).self) {
            _ = try CoseMessage.decode(CoseMessage.self, from: Data(hex: "5b0000000100000000"))
        }
    }

    @Test("Many NaN map keys are rejected in linear time")
    func nanKeysAreLinear() throws {
        let count = 4000
        var bytes = Data(hex: "d28440b9")
        bytes.append(UInt8(count >> 8)); bytes.append(UInt8(count & 0xff))
        for _ in 0..<count { bytes.append(Data(hex: "fa7fc0000000")) }
        bytes.append(Data(hex: "4040"))
        let start = Date()
        #expect(throws: (any Error).self) {
            _ = try CoseMessage.decode(Sign1Message.self, from: bytes)
        }
        // About 4 s before the fix in a debug build; tens of ms after.
        #expect(Date().timeIntervalSince(start) < 1.5)
    }

    // MARK: - Keys from received headers or COSE_Key

    @Test("RSA COSE_Keys with missing or mistyped components throw", arguments: [
        "A201032000",
        "A401032041012141012200",
        "A10103",
    ])
    func malformedRSAKeys(_ hex: String) throws {
        #expect(throws: (any Error).self) { _ = try CoseKey.decode(Data(hex: hex)) }
    }

    @Test("Messages carrying a malformed RSA header key throw", arguments: [
        "D08340A120A20103200040",
        "D28440A121A2010320004040",
    ])
    func malformedRSAHeaderKeys(_ hex: String) throws {
        #expect(throws: (any Error).self) {
            _ = try CoseMessage.decode(CoseMessage.self, from: Data(hex: hex))
        }
    }

    @Test("Partial EC2 and OKP public keys are refused at decode")
    func partialPublicKeys() throws {
        // EC2 with only y.
        #expect(throws: (any Error).self) {
            _ = try CoseKey.decode(Data(hex: "a3010220012258206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"))
        }
        // OKP with a text string x.
        #expect(throws: (any Error).self) {
            _ = try CoseKey.decode(Data(hex: "a301012006216161"))
        }
    }

    // MARK: - AEAD parameter checks

    @Test("AES-CCM with a short ciphertext or a wrong IV length throws", arguments: [
        "D08343A1010AA1054D0102030405060708090A0B0C0D4100",
        "d08343a1010aa1054d0101010101010101010101010144aabbccdd",
        "D08343A1010AA105500102030405060708090A0B0C0D0E0F105000112233445566778899AABBCCDDEEFF",
        "D08343A1010AA1054F0102030405060708090A0B0C0D0E0F5000112233445566778899AABBCCDDEEFF",
        "D08343A1010AA1054D0102030405060708090A0B0C0D5000112233445566778899AABBCCDDEEFF",
    ])
    func ccmMalformed(_ hex: String) throws {
        let msg = try CoseMessage.decode(Enc0Message.self, from: Data(hex: hex))
        msg.key = try CoseSymmetricKey(k: Self.key128)
        #expect(throws: (any Error).self) { _ = try msg.decrypt() }
    }

    @Test("AES-CCM-16 refuses a payload too long for its 2-byte length field")
    func ccmLengthLimit() throws {
        let aesCcm = AESCCM1664128()
        let key = try CoseSymmetricKey(k: Self.key128)
        let nonce = Data(repeating: 0x07, count: 13)
        _ = try aesCcm.encrypt(key: key, nonce: nonce, data: Data(count: 65535), aad: Data())
        #expect(throws: (any Error).self) {
            _ = try aesCcm.encrypt(key: key, nonce: nonce, data: Data(count: 65536), aad: Data())
        }
    }

    @Test("AES-GCM with a ciphertext shorter than the tag throws", arguments: [
        "d08343a10101a1054c0101010101010101010101014fababababababababababababababab",
        "d08343a10101a1054c01010101010101010101010141ab",
    ])
    func gcmShortCiphertext(_ hex: String) throws {
        let msg = try CoseMessage.decode(Enc0Message.self, from: Data(hex: hex))
        msg.key = try CoseSymmetricKey(k: Self.key128)
        #expect(throws: (any Error).self) { _ = try msg.decrypt() }
    }

    @Test("COSE_Encrypt with a direct recipient and a short GCM ciphertext throws")
    func gcmShortCiphertextEncrypt() throws {
        let msg = try CoseMessage.decode(EncMessage.self, from: Data(hex: "d8608443a10101a1054c01010101010101010101010148abababababababab818340a1012540"))
        msg.key = try CoseSymmetricKey(k: Self.key128)
        let recipient = try #require(msg.recipients.first)
        #expect(throws: (any Error).self) { _ = try msg.decrypt(recipient: recipient) }
    }

    @Test("AES-GCM refuses an IV that is not 12 bytes")
    func gcmIVLength() throws {
        let msg = Enc0Message(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data(repeating: 1, count: 4)],
            payload: Self.plaintext,
            key: try CoseSymmetricKey(k: Self.key128)
        )
        #expect(throws: (any Error).self) { _ = try msg.encode() }
    }

    // MARK: - Signatures

    @Test("An Ed448 signature with S + L is refused")
    func ed448NonCanonicalS() throws {
        let key = try OKPKey.generateKey(curve: Ed448Curve())
        let publicKey = try OKPKey(curve: Ed448Curve(), x: key.x)
        let data = Data("pay".utf8)
        let signature = try EdDSAAlgorithm().sign(key: key, data: data)
        #expect(try EdDSAAlgorithm().verify(key: publicKey, data: data, signature: signature))

        // S is the little-endian scalar in bytes 57..<114; add L to it.
        var bytes = [UInt8](signature)
        var carry = 0
        for i in 0..<57 {
            let order = i < EdDSAAlgorithm.ed448Order.count ? Int(EdDSAAlgorithm.ed448Order[i]) : 0
            let sum = Int(bytes[57 + i]) + order + carry
            bytes[57 + i] = UInt8(sum & 0xff)
            carry = sum >> 8
        }
        #expect(carry == 0)
        #expect(try EdDSAAlgorithm().verify(key: publicKey, data: data, signature: Data(bytes)) == false)
    }

    @Test("Rewriting an empty protected header from h'' to h'A0' breaks the tag")
    func emptyProtectedHeaderRewrite() throws {
        let key = try CoseSymmetricKey(k: Data(repeating: 0x07, count: 32))
        let msg = Mac0Message(uhdr: [Algorithm(): Hmac256()], payload: Data("hi".utf8), key: key)
        let encoded = try msg.encode()
        #expect(encoded[1] == 0x84 && encoded[2] == 0x40)

        let original = try CoseMessage.decode(Mac0Message.self, from: encoded)
        original.key = key
        #expect(try original.verifyTag())

        var rewritten = Data(encoded.prefix(2))
        rewritten.append(contentsOf: [0x41, 0xA0])
        rewritten.append(encoded.dropFirst(3))
        let decoded = try CoseMessage.decode(Mac0Message.self, from: rewritten)
        decoded.key = key
        #expect((try? decoded.verifyTag()) != true)
    }

    // MARK: - Recipients

    @Test("ECDH-SS refuses a header static key that is not the configured sender")
    func ecdhStaticKeyPinned() throws {
        let receiver = try EC2Key.generateKey(curve: P256Curve())
        let alice = try EC2Key.generateKey(curve: P256Curve())
        let mallory = try EC2Key.generateKey(curve: P256Curve())

        for alg in [EcdhSsHKDF256() as CoseAlgorithm, EcdhSsA128KW()] {
            let recipient: CoseRecipient = alg is EcdhSsHKDF256
                ? DirectKeyAgreement(phdr: [Algorithm(): alg])
                : KeyAgreementWithKeyWrap(phdr: [Algorithm(): alg])
            recipient.localAttrs = [StaticKey(): try Self.publicPart(of: receiver)]
            recipient.key = mallory
            let msg = EncMessage(
                phdr: [Algorithm(): A128GCM()],
                uhdr: [IV(): Data.randomBytes(count: 12)],
                payload: Self.plaintext,
                recipients: [recipient]
            )
            let encoded = try msg.encode()

            // Pinned to Alice: Mallory's message is refused.
            let decoded = try CoseMessage.decode(EncMessage.self, from: encoded)
            let decodedRecipient = try #require(decoded.recipients.first)
            decodedRecipient.key = receiver
            decodedRecipient.localAttrs = [StaticKey(): try Self.publicPart(of: alice)]
            #expect(throws: CoseError.self) { _ = try decoded.decrypt(recipient: decodedRecipient) }

            // Pinned to Mallory, or not pinned: it decrypts.
            decodedRecipient.localAttrs = [StaticKey(): try Self.publicPart(of: mallory)]
            #expect(try decoded.decrypt(recipient: decodedRecipient) == Self.plaintext)
            decodedRecipient.localAttrs = [:]
            #expect(try decoded.decrypt(recipient: decodedRecipient) == Self.plaintext)
        }
    }

    @Test("direct+HKDF recipients are refused instead of using the key raw")
    func directHKDFRefused() throws {
        let key = try CoseSymmetricKey(k: Data(count: 16))
        let enc = EncMessage(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data(repeating: 0x11, count: 12)],
            payload: Self.plaintext,
            key: key,
            recipients: [DirectEncryption(phdr: [Algorithm(): DirectHKDFSHA256()], uhdr: [Salt(): Data("aaaa".utf8)])]
        )
        #expect(throws: CoseError.self) { _ = try enc.encode() }

        let mac = MacMessage(
            phdr: [Algorithm(): Hmac256()],
            payload: Self.plaintext,
            key: try CoseSymmetricKey(k: Data(repeating: 7, count: 32)),
            recipients: [DirectEncryption(phdr: [Algorithm(): DirectHKDFSHA256()], uhdr: [Salt(): Data("s".utf8)])]
        )
        #expect(throws: CoseError.self) { _ = try mac.encode() }

        // Plain direct still works.
        let direct = EncMessage(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data(repeating: 0x11, count: 12)],
            payload: Self.plaintext,
            key: key,
            recipients: [DirectEncryption(uhdr: [Algorithm(): Direct()])]
        )
        let decoded = try CoseMessage.decode(EncMessage.self, from: try direct.encode())
        decoded.key = key
        #expect(try decoded.decrypt(recipient: try #require(decoded.recipients.first)) == Self.plaintext)
    }

    @Test("A key-wrap key bound to another algorithm or use is refused")
    func keyWrapKeyBinding() throws {
        let kek = Data.randomBytes(count: 16)
        let msg = EncMessage(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data.randomBytes(count: 12)],
            payload: Self.plaintext,
            recipients: [KeyWrap(uhdr: [Algorithm(): A128KW()], key: try CoseSymmetricKey(k: kek))]
        )
        let decoded = try CoseMessage.decode(EncMessage.self, from: try msg.encode())
        let recipient = try #require(decoded.recipients.first as? KeyWrap)

        recipient.key = try CoseSymmetricKey(k: kek, optionalParams: [KpAlg(): A128GCM()])
        #expect(throws: CoseError.self) { _ = try decoded.decrypt(recipient: recipient) }
        recipient.key = try CoseSymmetricKey(k: kek, optionalParams: [KpKeyOps(): [EncryptOp(), DecryptOp()]])
        #expect(throws: CoseError.self) { _ = try decoded.decrypt(recipient: recipient) }
        recipient.key = try CoseSymmetricKey(k: kek, optionalParams: [KpAlg(): A128KW(), KpKeyOps(): [UnwrapOp()]])
        #expect(try decoded.decrypt(recipient: recipient) == Self.plaintext)
    }

    @Test("An ECDH key bound to a signing algorithm is refused for key agreement")
    func keyAgreementKeyBinding() throws {
        let receiver = try EC2Key.generateKey(curve: P256Curve())
        let recipient = KeyAgreementWithKeyWrap(phdr: [Algorithm(): EcdhEsA128KW()])
        recipient.localAttrs = [StaticKey(): try Self.publicPart(of: receiver)]
        let msg = EncMessage(
            phdr: [Algorithm(): A128GCM()],
            uhdr: [IV(): Data.randomBytes(count: 12)],
            payload: Self.plaintext,
            recipients: [recipient]
        )
        let decoded = try CoseMessage.decode(EncMessage.self, from: try msg.encode())
        let decodedRecipient = try #require(decoded.recipients.first)
        let signingKey = try EC2Key(curve: P256Curve(), x: receiver.x, y: receiver.y, d: receiver.d)
        signingKey.alg = Es256()
        decodedRecipient.key = signingKey
        #expect(throws: CoseError.self) { _ = try decoded.decrypt(recipient: decodedRecipient) }
        decodedRecipient.key = receiver
        #expect(try decoded.decrypt(recipient: decodedRecipient) == Self.plaintext)
    }

    // MARK: - key_ops

    @Test("key_ops from a COSE_Key are kept and enforced")
    func keyOpsEnforced() throws {
        // {1: 4, -1: h'849B…', 4: [10]}: a symmetric key for MAC verify only.
        let key = try #require(try CoseKey.decode(Data(hex: "a301042050849B57219DAE48DE646D07DBB533566E04810a")))
        #expect(key.keyOps == [MacVerifyOp()])
        let symmetric = try #require(key as? CoseSymmetricKey)

        let mac = Mac0Message(phdr: [Algorithm(): Hmac256()], payload: Data("hi".utf8), key: try CoseSymmetricKey(k: Self.key128))
        let encoded = try mac.encode()
        let decoded = try CoseMessage.decode(Mac0Message.self, from: encoded)
        decoded.key = symmetric
        #expect(try decoded.verifyTag())

        // The same key cannot create a tag.
        let create = Mac0Message(phdr: [Algorithm(): Hmac256()], payload: Data("hi".utf8), key: symmetric)
        #expect(throws: CoseError.self) { _ = try create.encode() }

        // An unknown or wrong-type operation is refused at decode.
        #expect(throws: (any Error).self) {
            _ = try CoseKey.decode(Data(hex: "a301042050849B57219DAE48DE646D07DBB533566E04811863"))
        }
        #expect(throws: (any Error).self) {
            _ = try CoseKey.decode(Data(hex: "a301042050849B57219DAE48DE646D07DBB533566E048101"))
        }
    }

    @Test("A signing key restricted to verify cannot sign")
    func signKeyOps() throws {
        let generated = try OKPKey.generateKey(curve: Ed25519Curve())
        let verifyOnly = try OKPKey(curve: Ed25519Curve(), x: generated.x, d: generated.d, optionalParams: [KpKeyOps(): [VerifyOp()]])
        let msg = Sign1Message(phdr: [Algorithm(): EdDSAAlgorithm()], payload: Data("hi".utf8), key: verifyOnly)
        #expect(throws: CoseError.self) { _ = try msg.encode() }
    }

    // MARK: - Header values

    @Test("Header values without a CBOR form throw instead of becoming null")
    func headerValueEncoding() throws {
        #expect(try CBOR.fromCoseValue(UInt8(5)) == .unsignedInt(5))
        #expect(try CBOR.fromCoseValue(Int8(-2)) == .negativeInt(1))
        #expect(try CBOR.fromCoseValue(CBOR.textString("x")) == .textString("x"))
        #expect(throws: CoseError.self) { _ = try CBOR.fromCoseValue(Date()) }

        let msg = Sign1Message(
            phdr: [Algorithm(): EdDSAAlgorithm(), ContentType(): Date()],
            payload: Data("hi".utf8),
            key: try OKPKey.generateKey(curve: Ed25519Curve())
        )
        #expect(throws: (any Error).self) { _ = try msg.encode() }
    }

    // MARK: - X.509

    static func certificate() throws -> Data {
        let path = try #require(Bundle.module.path(forResource: "valid_certificate", ofType: "der", inDirectory: "data/x509"))
        return try Data(contentsOf: URL(fileURLWithPath: path))
    }

    @Test("X5Chain checks the requested key usage and the validity period")
    func x5chainChecks() throws {
        let inValidity = Date(timeIntervalSince1970: 1_750_000_000)
        let chain = try X5Chain(certData: try Self.certificate())
        #expect(try chain.verifyChain(keyUsage: ["digital_signature"], at: inValidity))
        #expect(try chain.verifyChain(keyUsage: ["key_cert_sign"], at: inValidity) == false)
        #expect(try chain.verifyChain(keyUsage: ["digital_signature"]) == false) // expired now
        #expect(throws: CoseError.self) { _ = try chain.verifyChain(keyUsage: ["bogus"], at: inValidity) }
        #expect(throws: CoseError.self) { _ = try X5Chain(certData: try Self.certificate(), verify: true) }
    }

    @Test("X5Chain path validation needs a trust root")
    func x5chainValidate() async throws {
        let inValidity = Date(timeIntervalSince1970: 1_750_000_000)
        let chain = try X5Chain(certData: try Self.certificate())
        #expect(await chain.validate(trustRoots: [], at: inValidity) == false)
        #expect(await chain.validate(trustRoots: [chain.certChain], at: inValidity))
    }
}
