import Foundation
import CBORCodable
import OrderedCollections

/// Abstract base class for COSE Mac messages (e.g., COSE_Mac and COSE_Mac0)
public class MacCommon: CoseMessage {

    // MARK: - Abstract Properties
    /// Abstract property to get the context of the message.
    public var context: String {
        fatalError("context must be implemented in subclasses.")
    }

    // MARK: - Properties
    public var authTag: Data = Data()
    
    /// Creates the mac_structure that needs to be MAC'ed.
    /// - Throws: `CoseError` if the structure cannot be created.
    /// - Returns: A serialized CBOR representation of the mac structure.
    public var macStructure: Data {
        get throws {
            guard self.payload != nil else {
                throw CoseError
                    .valueError("Payload cannot be empty for tag computation.")
            }
            
            var structure: [CBOR] = [CBOR.textString(context)]
            baseStructure(&structure)
            return try! CBORSerialization.data(from: .array(structure))
        }
    }

    // MARK: - Initialization
    public init(phdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                uhdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                payload: Data = Data(),
                externalAAD: Data = Data(),
                key: CoseSymmetricKey? = nil) {
        super.init(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: key
        )
        self.authTag = Data()
    }

    // MARK: - Methods
    /// Verifies the authentication tag of a received message.
    /// - Throws: `CoseError` if verification fails.
    /// - Returns: A Boolean indicating whether the verification succeeded.
    public func verifyTag() throws -> Bool {
        guard let targetAlgorithm = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }

        guard let key = self.key as? CoseSymmetricKey else {
            throw CoseError.invalidKey("Key must be of type SymmetricKey.")
        }

        try key
            .verify(
                keyType: CoseSymmetricKey.self,
                algorithm: targetAlgorithm,
                keyOps: [MacVerifyOp()]
            )
        
        if let alg = targetAlgorithm as? AesMacAlgorithm {
            return try alg.verifyTag(
                key: key,
                tag: self.authTag,
                data: self.macStructure
            )
        } else if let alg = targetAlgorithm as? HmacAlgorithm {
            return try alg.verifyTag(
                key: key,
                tag: self.authTag,
                data: self.macStructure
            )
        } else {
            throw CoseError.invalidAlgorithm("Unsupported algorithm")
        }
    }

    /// Computes the authentication tag of a COSE_Mac or COSE_Mac0 message.
    /// - Throws: `CoseError` if the tag computation fails.
    /// - Returns: The computed authentication tag as `Data`.
    public func computeTag() throws -> Data {
        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }
        
        guard let key = self.key as? CoseSymmetricKey else {
            throw CoseError.invalidKey("Key must be of type SymmetricKey.")
        }

        try key
            .verify(
                keyType: CoseSymmetricKey.self,
                algorithm: alg,
                keyOps: [MacCreateOp()]
            )
        
        if let alg = alg as? AesMacAlgorithm {
            self.authTag = try alg.computeTag(key: key, data: self.macStructure)
        } else if let alg = alg as? HmacAlgorithm {
            self.authTag = try alg.computeTag(key: key, data: self.macStructure)
        } else {
            throw CoseError.invalidAlgorithm("Unsupported algorithm")
        }
        return self.authTag
    }
}
