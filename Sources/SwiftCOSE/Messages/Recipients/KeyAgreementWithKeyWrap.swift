import Foundation
import CBORCodable

public class KeyAgreementWithKeyWrap: CoseRecipient {
    
    // MARK: - Properties
    public override var context: String {
        get { return _context }
        set { _context = newValue }
    }
    private var _context: String = ""
    
    // MARK: - Methods
    /// Decodes this recipient type, with its checks; see ``CoseRecipient/fromCoseObject(coseObj:)``.
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> KeyAgreementWithKeyWrap {
        return try fromCoseObject(coseObj: coseObj, context: nil)
    }
    
    public override class func fromCoseObject(coseObj: [CBOR], context: String? = nil) throws -> KeyAgreementWithKeyWrap {
        
        let msg = try super.fromCoseObject(
            coseObj: coseObj,
            context: context
        )
        
        let keyAgreementWithKeyWrapMsg = KeyAgreementWithKeyWrap(
            uhdr: msg.uhdr,
            payload: msg.payload ?? Data(),
            externalAAD: msg.externalAAD,
            key: msg.key as? CoseSymmetricKey ?? nil,
            recipients: msg.recipients
        )
        keyAgreementWithKeyWrapMsg.copyProtectedHeader(from: msg)
        
        // Set context if provided
        if let ctx = context {
            keyAgreementWithKeyWrapMsg.context = ctx
        }
        
        // The wrapped CEK travels in the ciphertext slot.
        guard let payload = keyAgreementWithKeyWrapMsg.payload, !payload.isEmpty else {
            throw CoseError.malformedMessage("Recipient class KEY_AGREEMENT_WITH_KEY_WRAP must carry the encrypted CEK in its payload.")
        }
        
        for recipient in keyAgreementWithKeyWrapMsg.recipients {
            recipient.context = "Rec_Recipient"
        }
        
        return keyAgreementWithKeyWrapMsg
    }
    
    public override func computeCEK(targetAlgorithm: EncAlgorithm, ops: String) throws -> CoseSymmetricKey? {
        return try deriveCEK(targetAlgorithm: targetAlgorithm, ops: ops)
    }
    
    override func deriveCEK(targetAlgorithm: CoseAlgorithm, ops: String) throws -> CoseSymmetricKey? {
        let keyOps = contentKeyOps(for: targetAlgorithm, ops: ops)
        if ops == "encrypt" {
            guard let payload, !payload.isEmpty else {
                return nil
            }
            return try CoseSymmetricKey(
                k: payload,
                optionalParams: [KpAlg(): targetAlgorithm, KpKeyOps(): keyOps]
            )
        } else {
            return try CoseSymmetricKey(
                k: unwrapCEK(),
                optionalParams: [KpAlg(): targetAlgorithm, KpKeyOps(): keyOps]
            )
        }
    }
    
    // MARK: - Encoding
    
    public override func encode(targetAlgorithm: CoseAlgorithm? = nil) throws -> [CBOR] {
        guard let alg = try getAttr(Algorithm()) as? EcdhHkdfAlgorithm else {
            throw CoseError.invalidAlgorithm("The algorithm parameter should be included in either the protected header or unprotected header.")
        }
        
        let encrypted = try wrapCEK()
        let staticAlgorithms: [CoseAlgorithmIdentifier] = [.ecdhSS_A128KW, .ecdhSS_A192KW, .ecdhSS_A256KW]
        if staticAlgorithms.contains(try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)) {
            // ECDH-SS: tell the receiver which static key we used.
            try includeStaticSenderKey()
        }
        var recipient: [CBOR] = [
            CBOR.byteString(try protectedHeaderBytes()),
            try CBOR.fromCoseValue(uhdrEncoded),
            try CBOR.fromCoseValue(encrypted)
        ]
        
        if !recipients.isEmpty {
            let recipientData = try recipients.map {
                CBOR.array(try $0.encode(targetAlgorithm: targetAlgorithm))
            }
            recipient.append(CBOR.array(recipientData))
        }
        
        return recipient
    }
    
    // MARK: - Key Management
    private func computeKEK(targetAlgorithm: EncAlgorithm, peerKey: EC2Key, localKey: EC2Key, kexAlgorithm: EcdhHkdfAlgorithm) throws -> Data {
        // ECDH uses our private key with the peer's public key.
        return try kexAlgorithm.deriveKEK(
            curve: localKey.curve,
            privateKey: localKey,
            publicKey: peerKey,
            context: getKDFContext(algorithm: targetAlgorithm)
        )
        
    }
    
    public func encrypt(targetAlgorithm: EncAlgorithm) throws -> Data {
        return try wrapCEK()
    }
    
    /// Wraps the CEK in `payload` with the agreed KEK. The KEK depends only
    /// on this recipient's own algorithm, so this works for any content
    /// algorithm, COSE_Mac included.
    func wrapCEK() throws -> Data {
        guard let payload else {
            throw CoseError.valueError("No CEK to wrap")
        }
        guard let alg = try getAttr(Algorithm()) as? EcdhHkdfAlgorithm else {
            throw CoseError.invalidAlgorithm("The algorithm parameter should at least be included in the unprotected header.")
        }
        
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)
        
        // Static receiver key
        guard let peerKey = localAttrs[StaticKey()] as? EC2Key else {
            throw CoseError.invalidKey("Static receiver key cannot be None. Should be configured in 'local_attrs' of the msg.")
        }
        
        let needsEphemeralKey: [CoseAlgorithmIdentifier] = [.ecdhES_A128KW, .ecdhES_A192KW, .ecdhES_A256KW]

        // Ephemeral key generation
        if key == nil {
            if needsEphemeralKey.contains(algId) {
                try setupEphemeralKey(peerKey: peerKey)
            } else {
                throw CoseError.invalidKey("Static sender key cannot be nil.")
            }
        }
        
        guard let localKey = key as? EC2Key else {
            throw CoseError.invalidKey("The sender key must be an EC2 key.")
        }
        if let peerEC2Key = peerKey as? EC2Key {
            try peerEC2Key.verify(keyType: EC2Key.self, algorithm: alg, keyOps: [DeriveKeyOp(), DeriveBitsOp()])
        }
        try localKey.verify(keyType: EC2Key.self, algorithm: alg, keyOps: [DeriveKeyOp(), DeriveBitsOp()])
        guard let wrapFunc = alg.keyWrapFunction as? AesKwAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm \(alg) has no AES key wrap function.")
        }
        
        let keyBytes = try computeKEK(
            targetAlgorithm: wrapFunc,
            peerKey: peerKey,
            localKey: localKey,
            kexAlgorithm: alg
        )
        
        return try wrapFunc.keyWrap(
            kek: CoseSymmetricKey(
                k: keyBytes,
                optionalParams: [
                    KpAlg(): alg,
                    KpKeyOps(): [WrapOp()]
                ]),
            data: payload
        )
    }
    
    public func decrypt(targetAlgorithm: EncAlgorithm) throws -> Data {
        return try unwrapCEK()
    }
    
    /// Unwraps the CEK carried in `payload` with the agreed KEK.
    func unwrapCEK() throws -> Data {
        guard let payload else {
            throw CoseError.valueError("No wrapped CEK to unwrap")
        }
        guard let alg = try getAttr(Algorithm()) as? EcdhHkdfAlgorithm else {
            throw CoseError.invalidAlgorithm("The algorithm parameter should at least be included in the unprotected header.")
        }
        
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)
        
        let needsEphemeralKey: [CoseAlgorithmIdentifier] = [.ecdhES_A128KW, .ecdhES_A192KW, .ecdhES_A256KW]
        let needsStaticKey: [CoseAlgorithmIdentifier] = [.ecdhSS_A128KW, .ecdhSS_A192KW, .ecdhSS_A256KW]
        
        let peerKey: CoseKey
        if needsEphemeralKey.contains(algId) {
            guard let ephermalKey = (try? getAttr(EphemeralKey())) as? CoseKey else {
                throw CoseError.invalidMessage("Ephemeral key is required.")
            }
            peerKey = ephermalKey
        } else if needsStaticKey.contains(algId) {
            guard let staticKey = try peerStaticKey() else {
                throw CoseError.invalidMessage("Static key is required.")
            }
            peerKey = staticKey
        } else {
            throw CoseError.invalidAlgorithm("Algorithm \(alg) not supported for \(type(of: self)).")
        }
        
        let keyOps = [DecryptOp(), UnwrapOp()]
        
        guard let peerEC2Key = peerKey as? EC2Key, let localKey = key as? EC2Key else {
            throw CoseError.invalidKey("Key agreement needs EC2 keys on both sides.")
        }
        // Check the caller's key (and the peer's) against this algorithm,
        // as DirectKeyAgreement does, so a key bound to another algorithm
        // or use is refused.
        try peerEC2Key.verify(keyType: EC2Key.self, algorithm: alg, keyOps: [DeriveKeyOp(), DeriveBitsOp()])
        try localKey.verify(keyType: EC2Key.self, algorithm: alg, keyOps: [DeriveKeyOp(), DeriveBitsOp()])
        guard let unwrapFunc = alg.keyWrapFunction as? AesKwAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm \(alg) has no AES key wrap function.")
        }
        
        let kek = try CoseSymmetricKey(
            k: try computeKEK(
                targetAlgorithm: unwrapFunc,
                peerKey: peerEC2Key,
                localKey: localKey,
                kexAlgorithm: alg
            ),
            optionalParams: [
                KpAlg(): alg,
                KpKeyOps(): keyOps
            ]
        )
        
        try kek.verify(
            keyType: CoseSymmetricKey.self,
            algorithm: alg,
            keyOps: keyOps
        )
        return try unwrapFunc.keyUnwrap(
            kek: kek,
            data: payload
        )
    }
    
    // MARK: - Debug Description
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate(payload?.base64EncodedString() ?? "nil")
        let recipientsDescription = recipients.map { $0.description }.joined(separator: ", ")
        
        return "<COSE_Recipient: [\(phdr), \(uhdr), \(payloadDescription), \(recipientsDescription)]>"
    }
}
