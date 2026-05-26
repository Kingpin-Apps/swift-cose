import Foundation
import CBORCodable

public class DirectKeyAgreement: CoseRecipient {
    
    // MARK: - Properties
    public override var context: String {
        get { return _context }
        set { _context = newValue }
    }
    private var _context: String = ""

    // MARK: - Methods
    public override class func fromCoseObject(coseObj: [CBOR], context: String? = nil) throws -> DirectKeyAgreement {
        
        let msg = try super.fromCoseObject(
            coseObj: coseObj
        )
        
        let directKeyAgreementMsg = DirectKeyAgreement(
            phdr: msg.phdr,
            uhdr: msg.uhdr,
            payload: msg.payload ?? Data(),
            externalAAD: msg.externalAAD,
            key: msg.key as? CoseSymmetricKey ?? nil
        )
        
        // Set context if provided
        if let ctx = context {
            directKeyAgreementMsg.context = ctx
        }
        
        // Validate algorithm and protected header
        guard let alg = try directKeyAgreementMsg.getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in protected headers")
        }
        
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)
        
        let needsEphemeralKey: [CoseAlgorithmIdentifier] = [.ecdhES_HKDF_256, .ecdhES_HKDF_512]
        
        let ephermalKey: Any?
        do {
            ephermalKey = try directKeyAgreementMsg.getAttr(EphemeralKey()) as Any
        }
        catch {
            ephermalKey = nil
        }
        
        if needsEphemeralKey.contains(algId) && ephermalKey == nil {
            throw CoseError.malformedMessage("Recipient class \(type(of: self))  must carry an ephemeral COSE key object.")
        }
        
        // Ensure there are no recipients
        guard directKeyAgreementMsg.recipients.isEmpty else {
            throw CoseError.malformedMessage("Recipient class \(type(of: self)) cannot carry more recipients.")
        }
        
        return directKeyAgreementMsg
    }

    // Encoding logic
    public override func encode(targetAlgorithm: CoseAlgorithm? = nil) throws -> [CBOR] {
        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("The algorithm parameter should be included in either the protected header or unprotected header.")
        }
        
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)

        // Static receiver key
        guard let peerKey = localAttrs[StaticKey()] as? EC2Key else {
            throw CoseError.invalidKey("Static receiver key cannot be nil. It should be configured in 'localAttributes' of the message.")
        }
        
        let needsEphemeralKey: [CoseAlgorithmIdentifier] = [.ecdhES_HKDF_256, .ecdhES_HKDF_512]

        // if ephemeral and not set, generate ephemeral key pair
        if key == nil {
            if needsEphemeralKey.contains(algId) {
                try setupEphemeralKey(peerKey: peerKey)
            } else {
                // alg uses a static sender
                throw CoseError.invalidKey("Static sender key cannot be nil.")
            }
        }
        
        if !recipients.isEmpty {
            throw CoseError.malformedMessage("Recipient class \(type(of: self)) must carry at least one recipient.")
        }
        
        // only the ephemeral sender key MUST be included in the header,
        // for the static sender it is recommended by not obligated
        let ephermalKey = try getAttr(EphemeralKey())
        if needsEphemeralKey.contains(algId) && ephermalKey == nil {
            throw CoseError.malformedMessage("Recipient class \(type(of: self))  must carry an ephemeral COSE key object.")
        }
        
        var recipient: [CBOR] = [
            CBOR.byteString(phdrEncoded),
            CBOR.fromAny(uhdrEncoded),
            CBOR.byteString(Data())
        ]

        if !recipients.isEmpty {
            let encodedRecipients = try recipients.map {
                CBOR.array(try $0.encode(targetAlgorithm: alg))
            }
            recipient.append(CBOR.array(encodedRecipients))
        }

        return recipient
    }
    
    // Compute KEK logic
    private func computeKEK(targetAlgorithm: EncAlgorithm, peerKey: EC2Key, localKey: EC2Key, kexAlg: EcdhHkdfAlgorithm) throws -> Data {
        return try kexAlg
            .deriveKEK(
                curve: peerKey.curve,
                privateKey: localKey,
                publicKey: peerKey,
                context: try getKDFContext(algorithm: targetAlgorithm)
            )
    }

    // Compute CEK logic
    public override func computeCEK(targetAlgorithm: EncAlgorithm, ops: String) throws -> CoseSymmetricKey? {
        guard let alg = try getAttr(Algorithm()) as? EcdhHkdfAlgorithm else {
            throw CoseError.invalidAlgorithm("The algorithm parameter should be included in either the protected header or unprotected header.")
        }
        
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)
        
        let supportedAlgorithms: [CoseAlgorithmIdentifier] = [
            .ecdhES_HKDF_256,
            .ecdhES_HKDF_512,
            .ecdhSS_HKDF_512,
            .ecdhSS_HKDF_512
        ]

        let peerKey: EC2Key
        if supportedAlgorithms.contains(algId) {
            if ops == "encrypt" {
                peerKey = localAttrs[StaticKey()] as! EC2Key
            } else {
                let algs: [CoseAlgorithmIdentifier] = [
                    .ecdhSS_HKDF_512,
                    .ecdhSS_HKDF_512
                ]
                if algs.contains(algId) {
                    peerKey = try getAttr(StaticKey()) as! EC2Key
                } else {
                    peerKey = try getAttr(EphemeralKey()) as! EC2Key
                }
            }
        } else {
            throw CoseError.invalidAlgorithm("Algorithm \(alg) unsupported for \(type(of: self)).")
        }

        try peerKey.verify(
            keyType: EC2Key.self,
            algorithm: alg,
            keyOps: [DeriveKeyOp(), DeriveBitsOp()]
        )
        try key?.verify(
            keyType: EC2Key.self,
            algorithm: alg,
            keyOps: [DeriveKeyOp(), DeriveBitsOp()]
        )

        return try CoseSymmetricKey(
            k: try computeKEK(
                targetAlgorithm: targetAlgorithm,
                peerKey: peerKey,
                localKey: key as! EC2Key,
                kexAlg: alg
            ),
            optionalParams: [KpAlg(): targetAlgorithm]
        )
    }

    // String representation
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let recipientsDescription = recipients.map { $0.description }.joined(separator: ", ")
        return "<COSE_Recipient: [\(phdr), \(uhdr), \(payloadDescription), \(recipientsDescription)]>"
    }
}
