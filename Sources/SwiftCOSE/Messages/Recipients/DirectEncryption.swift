import Foundation
import CBORCodable
import OrderedCollections

public class DirectEncryption: CoseRecipient {
    
    // MARK: - Properties
    public override var context: String {
        get { return _context }
        set { _context = newValue }
    }
    private var _context: String = ""
    
    // MARK: - Initialization
    public required init(phdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                         uhdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                         payload: Data = Data(),
                         externalAAD: Data = Data(),
                         key: CoseKey? = nil,
                         recipients: [CoseRecipient] = []) {
        super.init(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: key,
            recipients: recipients
        )
    }

    // MARK: - Methods
    public override class func fromCoseObject(coseObj: [CBOR], context: String? = nil) throws -> DirectEncryption {
        
        let msg = try super.fromCoseObject(
            coseObj: coseObj
        )
        
        let directEncryptionMsg = DirectEncryption(
            phdr: msg.phdr,
            uhdr: msg.uhdr,
            payload: msg.payload ?? Data(),
            externalAAD: msg.externalAAD,
            key: msg.key as? CoseSymmetricKey ?? nil
        )
        
        // Set context if provided
        if let ctx = context {
            directEncryptionMsg.context = ctx
        }
        
        // Check for zero-length payload
        guard let payload = directEncryptionMsg.payload, payload.isEmpty else {
            throw CoseError.malformedMessage("Recipient class DIRECT_ENCRYPTION must have a zero-length ciphertext.")
        }
        
        // Ensure there are no recipients
        guard directEncryptionMsg.recipients.isEmpty else {
            throw CoseError.malformedMessage("Recipient class DIRECT_ENCRYPTION cannot carry other recipients.")
        }
        
        let algorithm: CoseAlgorithm
//        let algId: CoseAlgorithmIdentifier
        
        algorithm = try (msg.getAttr(Algorithm()) as? CoseAlgorithm)!
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(algorithm)
        
        if algId == .direct && !directEncryptionMsg.phdr.isEmpty {
            throw CoseError.malformedMessage(
                "Recipient class DIRECT_ENCRYPTION with alg \(algorithm) must have a zero-length protected header."
            )
        }
        
        return directEncryptionMsg
    }
    
    // Encoding logic for DirectEncryption
    public override func encode(targetAlgorithm: CoseAlgorithm? = nil) throws -> [CBOR] {
        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Message must carry an algorithm parameter when using DIRECT_ENCRYPTION mode.")
        }
        let algId = try CoseAlgorithmIdentifier.fromCoseAlgorithm(alg)
        
        if algId == .direct && !phdr.isEmpty {
            throw CoseError.malformedMessage("Protected header must be empty.")
        }

        if !recipients.isEmpty {
            throw CoseError.invalidMessage("Recipient class DIRECT_ENCRYPTION cannot carry recipients.")
        }

        return [
            CBOR.byteString(phdrEncoded),
            CBOR.fromAny(uhdrEncoded),
            CBOR.byteString(Data())
        ]
    }

    // Compute Content Encryption Key (CEK)
    public func computeCEK(targetAlgorithm: CoseAlgorithm) throws -> CoseSymmetricKey? {
        let algorithm: CoseAlgorithm
        
        if let alg = try getAttr(Algorithm()) as? CoseAlgorithm {
            algorithm = alg
        } else {
            let algId = try getAttr(Algorithm())
            algorithm = try CoseAlgorithm.fromId(for: algId as Any)
        }
        
        if algorithm.identifier == CoseAlgorithmIdentifier.direct.rawValue {
            return nil
        } else {
            guard let key = key else {
                throw CoseError.invalidKey("No key available for deriving CEK.")
            }
            
            try key.verify(
                keyType: CoseSymmetricKey.self,
                algorithm: targetAlgorithm,
                keyOps: [DeriveKeyOp(), DeriveBitsOp()]
            )
            throw CoseError.notImplemented("Derivation for target algorithm is not yet implemented.")
        }
    }

    // Debug description
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let recipientsDescription = recipients.map { $0.description }.joined(separator: ", ")

        return "<COSE_Recipient: [\(phdr), \(uhdr), \(payloadDescription), \(recipientsDescription)]>"
    }
}
