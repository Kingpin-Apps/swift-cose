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
    public override class func fromCoseObject(coseObj: [CBOR], context: String? = nil) throws -> KeyAgreementWithKeyWrap {
        
        let msg = try super.fromCoseObject(
            coseObj: coseObj
        )
        
        let keyAgreementWithKeyWrapMsg = KeyAgreementWithKeyWrap(
            phdr: msg.phdr,
            uhdr: msg.uhdr,
            payload: msg.payload ?? Data(),
            externalAAD: msg.externalAAD,
            key: msg.key as? CoseSymmetricKey ?? nil
        )
        
        // Set context if provided
        if let ctx = context {
            keyAgreementWithKeyWrapMsg.context = ctx
        }
        
        // Check for zero-length payload
        guard let payload = keyAgreementWithKeyWrapMsg.payload, payload.isEmpty else {
            throw CoseError.malformedMessage("Recipient class KEY_AGREEMENT_WITH_KEY_WRAP must carry the encrypted CEK in its payload.")
        }
        
        for recipient in keyAgreementWithKeyWrapMsg.recipients {
            recipient.context = "Rec_Recipient"
        }
        
        return keyAgreementWithKeyWrapMsg
    }
    
    public override func computeCEK(targetAlgorithm: EncAlgorithm, ops: String) throws -> CoseSymmetricKey? {
        if ops == "encrypt" {
            if payload!.isEmpty {
                return nil
            } else {
                return try CoseSymmetricKey(
                    k: payload!,
                    optionalParams: [
                        KpAlg(): targetAlgorithm,
                        KpKeyOps(): [EncryptOp()]
                    ]
                )
            }
        } else {
            return try CoseSymmetricKey(
                k: decrypt(targetAlgorithm: targetAlgorithm),
                optionalParams: [
                    KpAlg(): targetAlgorithm,
                    KpKeyOps(): [DecryptOp()]
                ]
            )
        }
    }
    
    // MARK: - Encoding
    
    public override func encode(targetAlgorithm: CoseAlgorithm? = nil) throws -> [CBOR] {
        guard let alg = try getAttr(Algorithm()) as? EcdhHkdfAlgorithm else {
            throw CoseError.invalidAlgorithm("The algorithm parameter should be included in either the protected header or unprotected header.")
        }
        
        let encrypted = try encrypt(targetAlgorithm: alg.keyWrapFunction as! EncAlgorithm)
        var recipient: [CBOR] = [
            CBOR.byteString(phdrEncoded),
            CBOR.fromAny(uhdrEncoded),
            CBOR.fromAny(encrypted)
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
        return try kexAlgorithm.deriveKEK(
            curve: localKey.curve,
            privateKey: peerKey,
            publicKey: localKey,
            context: getKDFContext(algorithm: targetAlgorithm)
        )
        
    }
    
    public func encrypt(targetAlgorithm: EncAlgorithm) throws -> Data {
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
        
        let keyBytes = try computeKEK(
            targetAlgorithm: alg.keyWrapFunction as! EncAlgorithm,
            peerKey: peerKey,
            localKey: key as! EC2Key,
            kexAlgorithm: alg
        )
        let wrapFunc = alg.keyWrapFunction as? AesKwAlgorithm
        
        return try wrapFunc!.keyWrap(
            kek: CoseSymmetricKey(
                k: keyBytes,
                optionalParams: [
                    KpAlg(): alg,
                    KpKeyOps(): [DeriveKeyOp()]
                ]),
            data: payload!
        )
    }
    
    public func decrypt(targetAlgorithm: EncAlgorithm) throws -> Data {
        guard let alg = try getAttr(Algorithm()) as? EcdhHkdfAlgorithm else {
            throw CoseError.invalidAlgorithm("The algorithm parameter should at least be included in the unprotected header.")
        }
        
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)
        
        let needsEphemeralKey: [CoseAlgorithmIdentifier] = [.ecdhES_A128KW, .ecdhES_A192KW, .ecdhES_A256KW]
        let needsStaticKey: [CoseAlgorithmIdentifier] = [.ecdhSS_A128KW, .ecdhSS_A192KW, .ecdhSS_A256KW]
        
        let peerKey: CoseKey
        if needsEphemeralKey.contains(algId) {
            guard let ephermalKey = try getAttr(EphemeralKey()) as? CoseKey else {
                throw CoseError.invalidMessage("Ephemeral key is required.")
            }
            peerKey = ephermalKey
        } else if needsStaticKey.contains(algId) {
            guard let staticKey = try getAttr(StaticKey()) as? CoseKey else {
                throw CoseError.invalidMessage("Static key is required.")
            }
            peerKey = staticKey
        } else {
            throw CoseError.invalidAlgorithm("Algorithm \(alg) not supported for \(type(of: self)).")
        }
        
        let keyOps = [DecryptOp(), UnwrapOp()]
        
        let kek = try CoseSymmetricKey(
            k: try computeKEK(
                targetAlgorithm: alg.keyWrapFunction as! EncAlgorithm,
                peerKey: peerKey as! EC2Key,
                localKey: key as! EC2Key,
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
        return try (alg.keyWrapFunction as! AesKwAlgorithm).keyUnwrap(
            kek: kek,
            data: payload!
        )
    }
    
    // MARK: - Debug Description
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let recipientsDescription = recipients.map { $0.description }.joined(separator: ", ")
        
        return "<COSE_Recipient: [\(phdr), \(uhdr), \(payloadDescription), \(recipientsDescription)]>"
    }
}
