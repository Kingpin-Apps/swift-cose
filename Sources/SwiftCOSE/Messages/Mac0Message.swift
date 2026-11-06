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
    /// - Returns: A decoded Mac0Message instance.
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> Mac0Message {
        // COSE_Mac0 = [protected, unprotected, payload, tag]
        guard coseObj.count == 4, let authTag = coseObj[3].byteStringValue else {
            throw CoseError.invalidMessage("Missing or invalid authentication tag.")
        }
        let coseMessage = try super.fromCoseObject(
            coseObj: Array(coseObj.prefix(3))
        )
        
        let msg =  Mac0Message(
            uhdr: coseMessage.uhdr,
            externalAAD: coseMessage.externalAAD,
            key: coseMessage.key as? CoseSymmetricKey
        )
        msg.copyProtectedHeader(from: coseMessage)
        msg.payload = coseMessage.payload
        msg.authTag = authTag
        
        return msg
    }

    /// Encode and protect the COSE_Mac0 message.
    /// - Parameters:
    ///   - tag: Whether to include the CBOR tag.
    ///   - mac: Whether to compute the MAC tag. When false, the tag already in `authTag` is encoded.
    /// - Returns: The encoded message as `Data`.
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
        
        let result = try super.encode(message: message, tag: tag)
        
        return result
    }

    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate(payload?.base64EncodedString() ?? "nil")
        let authTagDescription = truncate((authTag.base64EncodedString()))

        return "<Mac0Message: [phdr: \(phdr), uhdr: \(uhdr), payload: \(String(describing: payloadDescription)), authTag: \(authTagDescription)]>"
    }
}
