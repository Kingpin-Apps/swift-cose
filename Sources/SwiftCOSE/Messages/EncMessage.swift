import Foundation
import CBORCodable
import OrderedCollections

/// EncMessage class for handling COSE_Encrypt messages.
public class EncMessage: EncCommon {
    // MARK: - Properties
    public override var context: String { "Encrypt" }
    public override var cborTag: Int { 96 }
    
    public var recipients: [CoseRecipient] {
        get {
            return _recipients
        }
        set {
            for recipient in newValue {
                _recipients.append(recipient)
            }
        }
    }

    private var _recipients: [CoseRecipient] = []

    // MARK: - Initialization
    /// Create a COSE_Encrypt message.
    /// - Parameters:
    ///   - phdr: Protected header bucket.
    ///   - uhdr: Unprotected header bucket.
    ///   - payload: The payload of the COSE_Encrypt message.
    ///   - externalAad: External additional data (is authenticated by not included in the final message)
    ///   - key: The Symmetric COSE key for encryption/decryption of the message
    ///   - recipients: An optional list of `CoseRecipient` objects.
    /// - Returns: A COSE Encrypt0 message object.
    public init(phdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                uhdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                 payload: Data = Data(),
                 externalAAD: Data = Data(),
                 key: CoseSymmetricKey? = nil,
                 recipients: [CoseRecipient]? = nil) {
        super.init(phdr: phdr,
                   uhdr: uhdr,
                   payload: payload,
                   externalAAD: externalAAD,
                   key: key)
        self.recipients = recipients ?? []
    }
    
    // MARK: - Methods
    /// Function to decode a COSE_Encrypt message
    /// - Parameter coseObj: The array to decode.
    /// - Returns: The decoded Enc0Message.
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> EncMessage {
        // Decode base message using the superclass method
        guard let msg = try super.fromCoseObject(coseObj: coseObj) as? EncMessage else {
            throw CoseError.invalidMessage("Failed to decode base EncMessage.")
        }
        
        do {
            // Attempt to parse recipients from the first element of coseObj
            if let recipientArray = coseObj.first?.arrayValue {
                for recipient in recipientArray {
                    guard let recipient = recipient.arrayValue else {
                        throw CoseError.valueError("Invalid recipient")
                    }
                    guard recipient.count == 3 else {
                        throw CoseError.valueError("Invalid recipient")
                    }
                    try msg.recipients
                        .append(
                            CoseRecipient
                                .createRecipient(
                                    recipient: recipient,
                                    context: "Enc_Recipient"
                                )
                        )
                }
            } else {
                msg.recipients = [] // If no recipients found, assign an empty array
            }
        } catch {
            throw CoseError.valueError("Failed to decode recipients.")
        }
        
        return msg
    }

    // MARK: - Encoding
    ///  Encodes and protects the COSE_Encrypt message
    /// - Parameters:
    ///   - tag: The boolean value which indicates if the COSE message will have a CBOR tag.
    ///   - encrypt: The boolean value which activates or deactivates the payload
    /// - Returns: The CBOR-encoded COSE Encrypt message.
    public func encode(tag: Bool = true, encrypt: Bool = true) throws -> Data {
        var message: [CBOR] = []

        if encrypt {
            let encrypted = try self.encrypt()
            message = [
                phdrEncoded.toCBOR,
                CBOR.fromAny(uhdrEncoded),
                CBOR.byteString(encrypted)
            ]
        } else {
            message = [
                phdrEncoded.toCBOR,
                CBOR.fromAny(uhdrEncoded),
                payload?.toCBOR ?? CBOR.null
            ]
        }
        
        if !self.recipients.isEmpty {
            guard let targetAlgorithm = try getAttr(Algorithm()) as? EncAlgorithm else {
                throw CoseError.invalidAlgorithm("Algorithm not found in headers")
            }
            
            let recipientData = try recipients.map {
                CBOR.array(try $0.encode(targetAlgorithm: targetAlgorithm))
            }
            message.append(CBOR.array(recipientData))
        }
        
        let result = try super.encode(message: message, tag: tag)
        
        return result
    }
    
    // MARK: - Encryption
    public override func encrypt() throws -> Data {
        guard let targetAlgorithm = try getAttr(Algorithm()) as? EncAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }
        
        let recipientTypes = try CoseRecipient.verifyRecipients(recipients)
        
        if recipientTypes.contains(describe(DirectEncryption.self)) {
            return try super.encrypt()
        } else if recipientTypes.contains(describe(DirectKeyAgreement.self)) {
            self.key = try recipients.first?
                .computeCEK(targetAlgorithm: targetAlgorithm, ops: "encrypt")
            return try super.encrypt()
        } else if recipientTypes.contains(describe(KeyWrap.self)) || recipientTypes.contains(describe(KeyAgreementWithKeyWrap.self)) {
            var keyBytes = Data.randomBytes(count: targetAlgorithm.keyLength!)
            
            for recipient in recipients {
                if ((recipient.payload?.isEmpty) != nil) {
                    recipient.payload = keyBytes
                } else {
                    keyBytes = recipient.payload!
                }
                if let recipient = recipient as? KeyAgreementWithKeyWrap {
                    let _ = try recipient.encrypt(targetAlgorithm: targetAlgorithm)
                } else if let recipient = recipient as? KeyWrap {
                    let _ = try recipient.encrypt(
                        targetAlgorithm: targetAlgorithm
                    )
                } else {
                    throw CoseError.unsupportedRecipient("Unsupported COSE recipient class")
                }
            }
            
            self.key = try CoseSymmetricKey(
                k: keyBytes,
                optionalParams: [KpAlg(): targetAlgorithm,
                                 KpKeyOps(): [EncryptOp()]]
            )
            return try super.encrypt()
        } else {
            throw CoseError.unsupportedRecipient("Unsupported COSE recipient class")
        }
    }

    // MARK: - Decryption
    public func decrypt(recipient: CoseRecipient) throws -> Data {
        guard let targetAlgorithm = try getAttr(Algorithm()) as? EncAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }
        
        guard CoseRecipient
            .hasRecipient(target: recipient, in: recipients) else {
            throw CoseError.valueError("Recipient not found")
        }
        
        let recipientTypes = try CoseRecipient.verifyRecipients(recipients)
        
        if recipientTypes.contains(describe(DirectEncryption.self)) {
            return try super.decrypt()
        } else if recipientTypes.contains(describe(DirectKeyAgreement.self)) || recipientTypes.contains(describe(KeyWrap.self)) || recipientTypes.contains(describe(KeyAgreementWithKeyWrap.self)) {
            self.key = try recipient
                .computeCEK(targetAlgorithm: targetAlgorithm, ops: "decrypt")
            return try super.decrypt()
        } else {
            throw CoseError.unsupportedRecipient("Unsupported COSE recipient class")
        }
    }
    
    // MARK: - Representation
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let recipientsDesc = recipients.map { $0.description }.joined(separator: ", ")
        return "<COSE_Recipient: [\(phdr), \(uhdr), \(truncate((self.payload?.base64EncodedString())!)), \(recipientsDesc)]"
    }
}
