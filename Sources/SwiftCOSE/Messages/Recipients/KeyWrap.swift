import Foundation
import CBORCodable

/// KeyWrap recipient type
public class KeyWrap: CoseRecipient {
    
    // MARK: - Properties
    public override var context: String {
        get { return _context }
        set { _context = newValue }
    }
    private var _context: String = ""
    
    // MARK: - Methods
    public override class func fromCoseObject(coseObj: [CBOR], context: String? = nil) throws -> KeyWrap {
        
        let msg = try CoseRecipient.fromCoseObject(
            coseObj: coseObj
        ) as CoseRecipient
            
        let keyWrapMsg = KeyWrap(
            phdr: msg.phdr,
            uhdr: msg.uhdr,
            payload: msg.payload ?? Data(),
            externalAAD: msg.externalAAD,
            key: msg.key as? CoseSymmetricKey ?? nil,
            recipients: msg.recipients
        )
        
        
        // Set context if provided
        if let ctx = context {
            keyWrapMsg.context = ctx
        }
        
        // Validate algorithm and protected header
        guard let alg = try keyWrapMsg.getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in protected headers")
        }
        
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)
        
        let needsZeroPHdr: [CoseAlgorithmIdentifier] = [.aesKW_128, .aesKW_192, .aesKW_256]
        if needsZeroPHdr.contains(algId) && !keyWrapMsg.phdr.isEmpty {
            throw CoseError.malformedMessage("Recipient class \(type(of: self)) must carry the encrypted CEK in its payload.")
        }
        
        for recipient in keyWrapMsg.recipients {
            recipient.context = "Rec_Recipient"
        }
        
        return keyWrapMsg
    }
    
    // MARK: - Encoding
    
    public override func encode(targetAlgorithm: CoseAlgorithm? = nil) throws -> [CBOR] {
        guard let alg = targetAlgorithm as? EncAlgorithm else {
            throw CoseError.invalidAlgorithm("The targetAlgorithm parameter should be included as an EncAlgorithm.")
        }
        
        var recipient: [CBOR] = [
            CBOR.byteString(phdrEncoded),
            CBOR.fromAny(uhdrEncoded),
            CBOR.byteString(try self.encrypt(targetAlgorithm: alg))
        ]
        
        if !recipients.isEmpty {
            let recipientData = try recipients.map {
                CBOR.array(try $0.encode(targetAlgorithm: alg))
            }
            recipient.append(CBOR.array(recipientData))
        }
        
        return recipient
    }
    
    // MARK: - Key Management
    
    private func computeKEK(targetAlgorithm: EncAlgorithm, ops: String) throws -> Data {
        guard let alg = try getAttr(Algorithm()) as? EncAlgorithm else {
            throw CoseError.invalidAlgorithm("The algorithm parameter should be included in either the protected header or unprotected header.")
        }
        
        if key == nil {
            if recipients.isEmpty {
                throw CoseError.invalidKey("No key found to \(ops) the CEK.")
            } else {
                let recipientTypes = try CoseRecipient.verifyRecipients(recipients)
                
                if ops == "encrypt" {
                    if recipientTypes.contains(String(describing: DirectKeyAgreement.self)) {
                        key = try recipients.first!
                            .computeCEK(targetAlgorithm: targetAlgorithm, ops: ops)
                    } else if recipientTypes.contains(String(describing: KeyWrap.self)) || recipientTypes.contains(String(describing: KeyAgreementWithKeyWrap.self)) {
                        
                        let keyBytes = Data.randomBytes(count: alg.keyLength!)
                        for recipient in recipients {
                            recipient.payload = keyBytes
                        }
                        key = try CoseSymmetricKey(k: keyBytes)
                    } else {
                        throw CoseError.unsupportedRecipient("Unsupported COSE recipient class.")
                    }
                } else {
                    if recipientTypes.contains(String(describing: DirectKeyAgreement.self)) || recipientTypes.contains(String(describing: KeyWrap.self)) || recipientTypes.contains(String(describing: KeyAgreementWithKeyWrap.self)) {
                        key = try recipients.first!.decrypt(targetAlgorithm: alg)
                    } else {
                        throw CoseError.unsupportedRecipient("Unsupported COSE recipient class.")
                    }
                }
            }
        }
        
        guard let key = self.key as? CoseSymmetricKey else {
            throw CoseError.invalidKey("No key found to decrypt the CEK.")
        }
        
        return key.k
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
    
    public func encrypt(targetAlgorithm: EncAlgorithm) throws -> Data {
        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("The algorithm parameter should be included in either the protected header or unprotected header.")
        }
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)
        
        if phdr.isEmpty {
            throw CoseError.invalidRecipientConfiguration("The algorithm parameter should at least be included in the unprotected header.")
        }
        
        let keyOps = [EncryptOp(), WrapOp()]
        
        switch algId {
            case .aesKW_128, .aesKW_192, .aesKW_256:
                let kek = try CoseSymmetricKey(
                    k: try computeKEK(targetAlgorithm: targetAlgorithm, ops: "encrypt"),
                    optionalParams: [KpAlg(): targetAlgorithm, KpKeyOps(): keyOps]
                )
                try kek.verify(
                    keyType: CoseSymmetricKey.self,
                    algorithm: alg,
                    keyOps: keyOps
                )
                return try (alg as! AesKwAlgorithm).keyWrap(
                    kek: kek,
                    data: payload!
                )
            case .rsa_ES_OAEP_SHA1, .rsa_ES_OAEP_SHA256, .rsa_ES_OAEP_SHA512:
                guard let kek = self.key as? RSAKey else {
                    throw CoseError.invalidKey("Invalid RSA key for encryption.")
                }
                try kek.verify(
                    keyType: RSAKey.self,
                    algorithm: alg,
                    keyOps: keyOps
                )
                return try (alg as! RsaOaep).keyWrap(
                    key: kek,
                    data: payload!
                )
            default:
                throw CoseError
                    .invalidAlgorithm(
                        "Algorithm \(String(describing: alg.fullname)) is not supported for KeyWrap."
                    )
        }

    }
    
    public func decrypt(targetAlgorithm: CoseAlgorithm) throws -> Data {
        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("The algorithm parameter should be included in either the protected header or unprotected header.")
        }
        
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)
        
        let keyOps = [DecryptOp(), UnwrapOp()]
        
        switch algId {
            case .aesKW_128, .aesKW_192, .aesKW_256:
                let kek = try CoseSymmetricKey(
                    k: try computeKEK(
                        targetAlgorithm: targetAlgorithm as! EncAlgorithm,
                        ops: "decrypt"
                    ),
                    optionalParams: [KpAlg(): targetAlgorithm, KpKeyOps(): keyOps]
                )
                try kek.verify(
                    keyType: CoseSymmetricKey.self,
                    algorithm: alg,
                    keyOps: keyOps
                )
                return try (alg as! AesKwAlgorithm).keyUnwrap(
                    kek: kek,
                    data: payload!
                )
            case .rsa_ES_OAEP_SHA1, .rsa_ES_OAEP_SHA256, .rsa_ES_OAEP_SHA512:
                guard let kek = self.key as? RSAKey else {
                    throw CoseError.invalidKey("Invalid RSA key for encryption.")
                }
                try kek.verify(
                    keyType: RSAKey.self,
                    algorithm: alg,
                    keyOps: keyOps
                )
                return try (alg as! RsaOaep).keyWrap(
                    key: kek,
                    data: payload!
                )
            default:
                throw CoseError
                    .invalidAlgorithm(
                        "Algorithm \(String(describing: alg.fullname)) is not supported for KeyWrap."
                    )
        }
    }
    
    // MARK: - Debug Description
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let recipientsDescription = recipients.map { $0.description }.joined(separator: ", ")
        
        return "<COSE_Recipient: [\(phdr), \(uhdr), \(payloadDescription), \(recipientsDescription)]>"
    }
}
