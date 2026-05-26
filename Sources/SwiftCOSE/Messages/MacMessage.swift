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
        var coseObj = coseObj
        let recipients = coseObj.popLast()
        let authTag = coseObj.popLast()
        let coseMessage = try super.fromCoseObject(
            coseObj: coseObj
        )
        
        let msg =  MacMessage(
            phdr: coseMessage.phdr,
            uhdr: coseMessage.uhdr,
            payload: coseMessage.payload!,
            externalAAD: coseMessage.externalAAD,
            key: coseMessage.key as? CoseSymmetricKey
        )
        
        // Extract and assign the authentication tag
        if authTag?.byteStringValue != nil {
            msg.authTag = authTag!.byteStringValue!
        } else {
            throw CoseError.valueError("Missing authentication tag in COSE object.")
        }

        // Attempt to decode recipients
        do {
            if let recipientArray = recipients?.arrayValue {
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
                                    context: "Mac_Recipient"
                                )
                        )
                }
            } else {
                msg.recipients = [] // No recipients present
            }
        } catch {
            throw CoseError.valueError("Failed to decode recipients.")
        }

        return msg
    }
    
    /// Encodes and protects the COSE_Mac message.
    /// - Parameters:
    ///   - tag: The boolean value which indicates if the COSE message will have a CBOR tag.
    ///   - mac: The boolean value which activates or deactivates the MAC tag.
    /// - Returns: The CBOR-encoded COSE Mac message.
    public func encode(tag: Bool = true, mac: Bool = true) throws -> Data {
        var message: [CBOR] = []
        
        if mac {
            let computedTag = try self.computeTag()
            message = [
                phdrEncoded.toCBOR,
                CBOR.fromAny(uhdrEncoded),
                payload?.toCBOR ?? CBOR.null,
                CBOR.byteString(computedTag)
            ]
        } else {
            message = [
                phdrEncoded.toCBOR,
                CBOR.fromAny(uhdrEncoded),
                payload?.toCBOR ?? CBOR.null]
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
        guard let targetAlgorithm = try? getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }

        let _ = try! CoseRecipient.verifyRecipients(recipients)

        if recipients.contains(where: { $0 is DirectEncryption }) {
            // Key should already be known
            return try super.computeTag()
        } else if recipients.contains(where: { $0 is DirectKeyAgreement }) {
            self.key = try! recipients.first?
                .computeCEK(
                    targetAlgorithm: targetAlgorithm as! EncAlgorithm,
                    ops: "encrypt"
                )
            return try super.computeTag()
        } else if recipients.contains(where: { $0 is KeyWrap }) || recipients.contains(where: { $0 is KeyAgreementWithKeyWrap }) {
            // Generate random key bytes
            var keyBytes = Data.randomBytes(count: (targetAlgorithm as! EncAlgorithm).keyLength!)
            
            for recipient in recipients {
                if recipient.payload?.isEmpty ?? true {
                    recipient.payload = keyBytes
                } else {
                    keyBytes = recipient.payload!
                }
                if let recipient = recipient as? KeyAgreementWithKeyWrap {
                    let _ = try recipient.encrypt(targetAlgorithm: targetAlgorithm as! EncAlgorithm)
                } else if let recipient = recipient as? KeyWrap {
                    let _ = try recipient.encrypt(
                        targetAlgorithm: targetAlgorithm as! EncAlgorithm
                    )
                } else {
                    throw CoseError.unsupportedRecipient("Unsupported COSE recipient class")
                }
            }

            self.key = try! CoseSymmetricKey(
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
    
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let authTagDescription = truncate((authTag.base64EncodedString()))
        let recipientsDescription = recipients.map { $0.description }.joined(separator: ", ")
        return "<COSE_Mac: [\(phdr), \(uhdr), \(payloadDescription), \(authTagDescription), [\(recipientsDescription)]]>"
    }
}
