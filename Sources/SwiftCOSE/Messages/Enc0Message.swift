import Foundation
import OrderedCollections
import CBORCodable

public class Enc0Message: EncCommon {
    public override var context: String { "Encrypt0" }
    public override var cborTag: Int { 16 }

    // MARK: - Initialization
    /// Create a COSE_encrypt0 message.
    /// - Parameters:
    ///   - phdr: Protected header bucket.
    ///   - uhdr: Unprotected header bucket.
    ///   - payload: The payload (will be encrypted and authenticated).
    ///   - externalAad: External data (is authenticated but not transported in the message).
    ///   - key: The Symmetric COSE key for encryption/decryption of the message
    /// - Returns: A COSE Encrypt0 message object.
    public override init(phdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                         uhdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                         payload: Data = Data(),
                         externalAAD: Data = Data(),
                         key: CoseSymmetricKey? = nil) {
        super.init(phdr: phdr,
                   uhdr: uhdr,
                   payload: payload,
                   externalAAD: externalAAD,
                   key: key)
    }
    
    // MARK: - Methods
    /// Function to decode a COSE_Encrypt0 message
    /// - Parameter coseObj: The array to decode.
    /// - Returns: The decoded Enc0Message.
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> Enc0Message {
        let coseObject = try super.fromCoseObject(
            coseObj: coseObj
        )
        
        return Enc0Message(
            phdr: coseObject.phdr,
            uhdr: coseObject.uhdr,
            payload: coseObject.payload ?? Data(),
            externalAAD: coseObject.externalAAD,
            key: coseObject.key as? CoseSymmetricKey
        )
    }

    // MARK: - Encoding
    /// Encode and protect the COSE_Encrypt0 message.
    /// - Parameters:
    ///   - tag: Boolean value which indicates if the COSE message will have a CBOR tag.
    ///   - encrypt: Boolean which activates or deactivates the payload protection.
    /// - Returns: A CBOR-encoded COSE Encrypt0 message.
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
        
        let result = try super.encode(message: message, tag: tag)
        
        return result
    }
    
    // Custom description for the object
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()

        return "<COSE_Encrypt0: [\(phdr), \(uhdr), \(truncate((self.payload?.base64EncodedString())!))]>"
    }
}
