import Foundation
import CBORCodable
import OrderedCollections

/// A COSE Sign1Message class, representing a COSE single signature message.
public class Sign1Message: SignCommon {
    // MARK: - Properties
    public var context: String { "Signature1" }
    public override var cborTag: Int { 18 }

    public override var signature: Data {
        get {
            return _signature
        }
        set {
            _signature = newValue
        }
    }
    private var _signature: Data = Data()

    // MARK: - Initialization
    public init(
        phdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
        uhdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
        payload: Data = Data(),
        externalAAD: Data = Data(),
        key: CoseKey? = nil,
        recipients: [CoseRecipient] = []
    ) {
        super.init(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: key)
    }

    // MARK: - Methods

    /// Decodes a COSE Sign1Message from a CBOR object.
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> Sign1Message {
        guard coseObj.count == 4, let signature = coseObj[3].byteStringValue else {
            throw CoseError.invalidMessage("Missing or invalid signature.")
        }
        let coseMessage = try super.fromCoseObject(
            coseObj: Array(coseObj.prefix(3))
        )
        
        let msg = Sign1Message(
            uhdr: coseMessage.uhdr,
            externalAAD: coseMessage.externalAAD,
            key: coseMessage.key
        )
        msg.copyProtectedHeader(from: coseMessage)
        msg.payload = coseMessage.payload
        msg.signature = signature

        return msg
    }

    /// Encodes the Sign1Message as a CBOR structure with an optional tag.
    public func encode(tag: Bool = true, sign: Bool = true, detachedPayload: Data? = nil) throws
        -> Data
    {
        var cborMessage: [CBOR]
        // RFC 9052, section 2: a detached payload is sent as nil.
        let payloadItem: CBOR = detachedPayload != nil
            ? CBOR.null
            : (payload.map { CBOR.byteString($0) } ?? CBOR.null)

        if sign {
            let computedSignature = try self.computeSignature(detachedPayload: detachedPayload)
            cborMessage = [
                CBOR.byteString(try protectedHeaderBytes()),
                try CBOR.fromCoseValue(uhdrEncoded),
                payloadItem,
                CBOR.byteString(computedSignature),
            ]
        } else {
            // Re-emit the signature already held; COSE_Sign1 always has one.
            guard !signature.isEmpty else {
                throw CoseError.valueError("No signature to encode; use sign: true or set signature.")
            }
            cborMessage = [
                CBOR.byteString(try protectedHeaderBytes()),
                try CBOR.fromCoseValue(uhdrEncoded),
                payloadItem,
                CBOR.byteString(signature),
            ]
        }

        if tag {
            return try CBORSerialization.data(
                from:
                    CBOR
                    .tagged(
                        UInt64(cborTag),
                        CBOR.array(cborMessage)
                    )
            )
        } else {
            return try CBORSerialization.data(from: .array(cborMessage))
        }
    }

    /// Computes the signature structure that needs to be signed.
    public override func createSignatureStructure(detachedPayload: Data? = nil) throws -> Data {
        var sigStructure: [CBOR] = [CBOR.textString(context)]
        try baseStructure(&sigStructure)

        if detachedPayload == nil {
            guard let payload = self.payload else {
                throw
                    CoseError
                    .valueError("Missing payload and no detached payload provided.")
            }
            sigStructure.append(CBOR.byteString(payload))
        } else {
            guard self.payload == nil || self.payload == Data() else {
                throw CoseError.valueError("Detached payload must be None when payload is set.")
            }
            sigStructure.append(CBOR.byteString(detachedPayload!))
        }

        return try CBORSerialization.data(from: .array(sigStructure))
    }

    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate(payload?.base64EncodedString() ?? "nil")
        let signatureDescription = truncate((signature.base64EncodedString()))
        return "<COSE_Sign1: [\(phdr), \(uhdr), \(payloadDescription), \(signatureDescription)]>"
    }
}
