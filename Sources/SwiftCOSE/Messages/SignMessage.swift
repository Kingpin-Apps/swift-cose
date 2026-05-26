import Foundation
import CBORCodable
import OrderedCollections

/// Abstract class representing a COSE Sign Message.
public class CoseSignMessage: CoseMessage {
    
    // MARK: - Abstract Properties
    public var context: String {
        fatalError("Subclasses must implement the 'context' property")
    }
    
    // MARK: - Properties
    
    /// The signers of the message.
    public var signers: [CoseSignature] {
        get {
            return _signers
        }
        set {
            for signer in newValue {
                signer.parent = self
            }
            _signers = newValue
        }
    }
    private var _signers: [CoseSignature] = []
    
    // MARK: - Initialization
    public init(
        phdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
        uhdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
        payload: Data? = nil,
        signers: [CoseSignature] = []
    ) {
        super.init(phdr: phdr, uhdr: uhdr, payload: payload)
        self.signers = signers
    }
    
    // MARK: - Methods
    /// Decodes a COSE_Sign message from a CBOR object.
    /// - Parameters:
    ///   - coseObj: The CBOR object to decode.
    ///   - allowUnknownAttributes: Whether to allow unknown attributes.
    /// - Returns: The decoded SignMessage.
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> CoseSignMessage {
        var coseObj = coseObj
        let signers = coseObj.popLast()
        let coseMessage = try super.fromCoseObject(
            coseObj: coseObj
        )
        
        let msg =  CoseSignMessage(
            phdr: coseMessage.phdr,
            uhdr: coseMessage.uhdr,
            payload: coseMessage.payload!
        )
        
        guard signers != nil  else {
            throw CoseError.invalidMessage("Missing or invalid signers.")
        }
        
        // Attempt to decode signers
        do {
            if let signersArray = signers?.arrayValue {
                for signer in signersArray {
                    guard let signer = signer.arrayValue else {
                        throw CoseError.valueError("Invalid signer")
                    }
                    guard signer.count >= 3 else {
                        throw CoseError.valueError("Invalid signer")
                    }
                    msg.signers
                        .append(try CoseSignature.fromCoseObject(coseObj: signer))
                }
            } else {
                msg.signers = [] // No signers present
            }
        } catch {
            throw CoseError
                .valueError(
                    "Failed to decode signers. \(error.localizedDescription)"
                )
        }
        return msg
    }
    
    /// Encodes the message to CBOR.
    /// - Parameters:
    ///   - tag: Whether to include a CBOR tag.
    ///   - detachedPayload: An optional detached payload.
    /// - Returns: The encoded message as Data.
    public func encode(tag: Bool = true, detachedPayload: Data? = nil) throws -> Data {
        var cborMessage: [CBOR] = []
        cborMessage.append(phdrEncoded.toCBOR)
        cborMessage.append(CBOR.fromAny(uhdrEncoded))
        cborMessage.append(payload?.toCBOR ?? CBOR.null)
        
        if !signers.isEmpty {
            let encodedSigners = try signers.map {
                CBOR.array(try $0.encode(detachedPayload: detachedPayload))
            }
            cborMessage.append(CBOR.array(encodedSigners))
        }
        
        if tag {
            return try CBORSerialization.data(
                from: CBOR
                    .tagged(
                        UInt64(cborTag),
                        CBOR.array(cborMessage)
                    )
            )
        } else {
            return try CBORSerialization.data(from: .array(cborMessage))
        }
    }
    
    // MARK: - Description
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let signersDescription = signers.map { $0.description }.joined(separator: ", ")
        return "<COSE_Sign: [\(phdr), \(uhdr), \(payloadDescription), [\(signersDescription)]]>"
    }
}


public class SignMessage: CoseSignMessage {
    // MARK: - Properties
    public override var context: String { "Signature" }
    public override var cborTag: Int { 98 }
}
