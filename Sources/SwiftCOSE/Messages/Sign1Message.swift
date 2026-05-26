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
        var coseObj = coseObj
        let signature = coseObj.popLast()
        let coseMessage = try super.fromCoseObject(
            coseObj: coseObj
        )
        
        let msg = Sign1Message(
            phdr: coseMessage.phdr,
            uhdr: coseMessage.uhdr,
            payload: coseMessage.payload!,
            externalAAD: coseMessage.externalAAD,
            key: coseMessage.key
        )

        guard signature != nil else {
            throw CoseError.invalidMessage("Missing or invalid signature.")
        }

        msg.signature = signature!.byteStringValue!

        return msg
    }

    /// Encodes the Sign1Message as a CBOR structure with an optional tag.
    public func encode(tag: Bool = true, sign: Bool = true, detachedPayload: Data? = nil) throws
        -> Data
    {
        var cborMessage: [CBOR]

        if sign {
            let computedSignature = try self.computeSignature(detachedPayload: detachedPayload)
            cborMessage = [
                CBOR.byteString(phdrEncoded),
                CBOR.fromAny(uhdrEncoded),
                CBOR.byteString(payload ?? Data()),
                CBOR.byteString(computedSignature),
            ]
        } else if !signature.isEmpty {
            cborMessage = [
                CBOR.byteString(phdrEncoded),
                CBOR.fromAny(uhdrEncoded),
                CBOR.byteString(payload ?? Data()),
                CBOR.byteString(signature),
            ]
        } else {
            cborMessage = [
                CBOR.byteString(phdrEncoded),
                CBOR.fromAny(uhdrEncoded),
                CBOR.byteString(payload ?? Data()),
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
        baseStructure(&sigStructure)

        if detachedPayload == nil {
            guard let payload = self.payload else {
                throw
                    CoseError
                    .valueError("Missing payload and no detached payload provided.")
            }
            sigStructure.append(CBOR(payload))
        } else {
            guard self.payload != nil else {
                throw CoseError.valueError("Detached payload must be None when payload is set.")
            }
            sigStructure.append(detachedPayload!.toCBOR)
        }

        return try CBORSerialization.data(from: .array(sigStructure))
    }

    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let signatureDescription = truncate((signature.base64EncodedString()))
        return "<COSE_Sign1: [\(phdr), \(uhdr), \(payloadDescription), \(signatureDescription)]>"
    }
}
