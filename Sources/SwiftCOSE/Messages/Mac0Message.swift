import Foundation
import CBORCodable
import OrderedCollections

/// COSE_Mac0 message type
public class Mac0Message: MacCommon {
    // MARK: - Properties
    public override var context: String { "MAC0" }
    public override var cborTag: Int { 17 }

    // MARK: - Initialization
    public override init(
        phdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
        uhdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
        payload: Data = Data(),
        externalAAD: Data = Data(),
        key: CoseSymmetricKey? = nil
    ) {
        super.init(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: key
        )
    }

    // MARK: - Methods
    /// Decode a Mac0Message from a COSE object.
    /// - Parameters:
    ///   - coseObj: The COSE object represented as a CBOR array.
    ///   - allowUnknownAttributes: Flag to allow unknown attributes.
    /// - Returns: A decoded Mac0Message instance.
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> Mac0Message {
        var coseObj = coseObj
        let authTag = coseObj.popLast()
        let coseMessage = try super.fromCoseObject(
            coseObj: coseObj
        )
        
        let msg =  Mac0Message(
            phdr: coseMessage.phdr,
            uhdr: coseMessage.uhdr,
            payload: coseMessage.payload!,
            externalAAD: coseMessage.externalAAD,
            key: coseMessage.key as? CoseSymmetricKey
        )
        msg.authTag = authTag!.byteStringValue!
        
        return msg
    }

    /// Encode and protect the COSE_Mac0 message.
    /// - Parameters:
    ///   - tag: Whether to include the CBOR tag.
    ///   - mac: Whether to compute the MAC tag.
    /// - Returns: The encoded message as `Data`.
    public func encode(tag: Bool = true, mac: Bool = true) throws -> Data {
        var message: [CBOR] = []
        
        if mac {
            let computedTag = try self.computeTag()
            message = [
                phdrEncoded.toCBOR,
                CBOR.fromAny(uhdrEncoded),
                payload?.toCBOR ?? CBOR.null,
                CBOR.fromAny(computedTag)
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

    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let authTagDescription = truncate((authTag.base64EncodedString()))

        return "<Mac0Message: [phdr: \(phdr), uhdr: \(uhdr), payload: \(String(describing: payloadDescription)), authTag: \(authTagDescription)]>"
    }
}
