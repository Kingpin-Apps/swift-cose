import Foundation
import CBORCodable
import OrderedCollections

/// COSE MACed Message with Recipients
public class MacMessage: MacCommon {
    // MARK: - Properties
    public override var context: String { "MAC" }
    public override var cborTag: Int { 97 }
    public var recipients: [CoseRecipient] = []
    
    // MARK: - Initialization
    public init(phdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                uhdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                payload: Data = Data(),
                externalAAD: Data = Data(),
                key: CoseSymmetricKey? = nil,
                recipients: [CoseRecipient] = []) {
        super.init(phdr: phdr,
                   uhdr: uhdr,
                   payload: payload,
                   externalAAD: externalAAD,
                   key: key)
        self.recipients = recipients
    }
    
    // MARK: - Methods
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> MacMessage {
        // COSE_Mac = [protected, unprotected, payload, tag, recipients]
        guard coseObj.count == 5 else {
            throw CoseError.invalidMessage("COSE_Mac must have five elements.")
        }
        guard let authTag = coseObj[3].byteStringValue else {
            throw CoseError.valueError("Missing authentication tag in COSE object.")
        }
        guard let recipientArray = coseObj[4].arrayValue else {
            throw CoseError.invalidMessage("COSE_Mac must carry an array of recipients.")
        }
        let coseMessage = try super.fromCoseObject(
            coseObj: Array(coseObj.prefix(3))
        )
        
        let msg =  MacMessage(
            uhdr: coseMessage.uhdr,
            externalAAD: coseMessage.externalAAD,
            key: coseMessage.key as? CoseSymmetricKey
        )
        msg.copyProtectedHeader(from: coseMessage)
        msg.payload = coseMessage.payload
        msg.authTag = authTag

        // Attempt to decode recipients
        do {
            for recipient in recipientArray {
                guard let recipient = recipient.arrayValue, recipient.count >= 3 else {
                    throw CoseError.valueError("Invalid recipient")
                }
                msg.recipients.append(
                    try CoseRecipient.createRecipient(
                        recipient: recipient,
                        context: "Mac_Recipient"
                    )
                )
            }
        } catch {
            throw CoseError.valueError("Failed to decode recipients: \(error)")
        }

        return msg
    }
    
    /// Encodes and protects the COSE_Mac message.
    /// - Parameters:
    ///   - tag: The boolean value which indicates if the COSE message will have a CBOR tag.
    ///   - mac: Whether to compute the MAC tag. When false, the tag already in `authTag` is encoded.
    /// - Returns: The CBOR-encoded COSE Mac message.
    public func encode(tag: Bool = true, mac: Bool = true) throws -> Data {
        var message: [CBOR] = []
        
        if mac {
            let computedTag = try self.computeTag()
            message = [
                CBOR.byteString(phdrEncoded),
                CBOR.fromAny(uhdrEncoded),
                payload.map { CBOR.byteString($0) } ?? CBOR.null,
                CBOR.byteString(computedTag)
            ]
        } else {
            // Re-emit the tag already held (for example from decoding);
            // the structure always carries one.
            guard !authTag.isEmpty else {
                throw CoseError.valueError("No authentication tag to encode; use mac: true or set authTag.")
            }
            message = [
                CBOR.byteString(phdrEncoded),
                CBOR.fromAny(uhdrEncoded),
                payload.map { CBOR.byteString($0) } ?? CBOR.null,
                CBOR.byteString(authTag)
            ]
        }
        
        if !self.recipients.isEmpty {
            guard let targetAlgorithm = try getAttr(Algorithm()) as? CoseAlgorithm else {
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
    
    public override func computeTag() throws -> Data {
        guard let targetAlgorithm = (try? getAttr(Algorithm())) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }

        let _ = try CoseRecipient.verifyRecipients(recipients)

        if recipients.contains(where: { $0 is DirectEncryption }) {
            // Key should already be known
            return try super.computeTag()
        } else if recipients.contains(where: { $0 is DirectKeyAgreement }) {
            self.key = try recipients.first?
                .deriveCEK(targetAlgorithm: targetAlgorithm, ops: "encrypt")
            return try super.computeTag()
        } else if recipients.contains(where: { $0 is KeyWrap }) || recipients.contains(where: { $0 is KeyAgreementWithKeyWrap }) {
            // Generate random key bytes
            var keyBytes = Data.randomBytes(count: try contentKeyLength(for: targetAlgorithm))
            
            for recipient in recipients {
                if let payload = recipient.payload, !payload.isEmpty {
                    keyBytes = payload
                } else {
                    recipient.payload = keyBytes
                }
                if let recipient = recipient as? KeyAgreementWithKeyWrap {
                    let _ = try recipient.wrapCEK()
                } else if let recipient = recipient as? KeyWrap {
                    let _ = try recipient.wrapCEK(targetAlgorithm: targetAlgorithm)
                } else {
                    throw CoseError.unsupportedRecipient("Unsupported COSE recipient class")
                }
            }

            self.key = try CoseSymmetricKey(
                k: keyBytes,
                optionalParams: [
                    KpAlg(): targetAlgorithm,
                    KpKeyOps(): [MacCreateOp()]
                ]
            )
            return try super.computeTag()
        } else {
            throw CoseError.unsupportedRecipient("Unsupported COSE recipient class")
        }
    }
    
    /// Verifies the tag of a received COSE_Mac with the key one recipient
    /// carries.
    ///
    /// For a direct recipient, set ``CoseMessage/key`` to the shared MAC key
    /// first. For key wrap and key agreement recipients, set the recipient's
    /// own key (the KEK, or the receiver's private EC2 key); the MAC key is
    /// recovered from the recipient.
    /// - Parameter recipient: One of this message's ``recipients``.
    /// - Returns: `true` if the tag is valid.
    public func verifyTag(recipient: CoseRecipient) throws -> Bool {
        guard let targetAlgorithm = (try? getAttr(Algorithm())) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }
        guard CoseRecipient.hasRecipient(target: recipient, in: recipients) else {
            throw CoseError.valueError("Recipient not found")
        }
        let _ = try CoseRecipient.verifyRecipients(recipients)
        
        if recipient is DirectEncryption {
            return try verifyTag()
        } else if recipient is DirectKeyAgreement || recipient is KeyWrap || recipient is KeyAgreementWithKeyWrap {
            self.key = try recipient.deriveCEK(targetAlgorithm: targetAlgorithm, ops: "decrypt")
            return try verifyTag()
        } else {
            throw CoseError.unsupportedRecipient("Unsupported COSE recipient class")
        }
    }
    
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate(payload?.base64EncodedString() ?? "nil")
        let authTagDescription = truncate((authTag.base64EncodedString()))
        let recipientsDescription = recipients.map { $0.description }.joined(separator: ", ")
        return "<COSE_Mac: [\(phdr), \(uhdr), \(payloadDescription), \(authTagDescription), [\(recipientsDescription)]]>"
    }
}
