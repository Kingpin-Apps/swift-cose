import Foundation
import CBORCodable
import OrderedCollections

// MARK: - EncCommon

public class EncCommon: CoseMessage {
    // MARK: - Abstract Properties
    public override var cborTag: Int {
        fatalError("cborTag must be overridden in subclass.")
    }
    public var context: String {
        fatalError("Subclasses must implement the `context` property.")
    }
    
    // MARK: - Properties
    /// Build the encryption context.
    private var encStructure: Data {
        get throws {
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
    }

    // MARK: - Methods
    /// Decrypts the payload.
    /// - Returns: plaintext as bytes.
    /// - Throws: `CoseError` if decryption fails.
    public func decrypt() throws -> Data {
        guard let key = self.key else {
            throw CoseError.invalidKey("Key cannot be nil")
        }

        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }

        let nonce = try getNonce()
        
        try key
            .verify(
                keyType: CoseSymmetricKey.self,
                algorithm: alg,
                keyOps: [DecryptOp()]
            )
        
        if let alg = alg as? AesCcmAlgorithm {
            return try alg
                .decrypt(
                    key: key as! CoseSymmetricKey,
                    nonce: nonce,
                    ciphertext: payload!,
                    aad: encStructure
                )
        } else if let alg = alg as? AesGcmAlgorithm {
            return try alg
                .decrypt(
                    key: key as! CoseSymmetricKey,
                    nonce: nonce,
                    ciphertext: payload!,
                    aad: encStructure
                )
        } else {
            throw CoseError.invalidAlgorithm("Unsupported algorithm")
        }
    }
    
    /// Encrypts the payload.
    /// - Returns: ciphertext as bytes.
    /// - Throws: `CoseError` when the key is not of type 'SymmetricKey'.
    public func encrypt() throws -> Data {
        guard let key = self.key else {
            throw CoseError.invalidKey("Key cannot be nil")
        }
        
        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }

        let nonce = try getNonce()
        
        try key
            .verify(
                keyType: CoseSymmetricKey.self,
                algorithm: alg,
                keyOps: [EncryptOp()]
            )
        
        if let alg = alg as? AesCcmAlgorithm {
            return try alg
                .encrypt(
                    key: key as! CoseSymmetricKey,
                    nonce: nonce,
                    data: payload!,
                    aad: encStructure
                )
        } else if let alg = alg as? AesGcmAlgorithm {
            return try alg
                .encrypt(
                    key: key as! CoseSymmetricKey,
                    nonce: nonce,
                    data: payload!,
                    aad: encStructure
                )
        } else {
            throw CoseError.invalidAlgorithm("Unsupported algorithm")
        }
    }

    private func getNonce() throws -> Data {
        // Attempt to retrieve the IV attribute
        let nonce = try getAttr(IV()) as? Data
        
        if nonce == nil, let baseIV = self.key?.baseIV, !baseIV.isEmpty {
            // Retrieve the PartialIV attribute
            guard let partialIV = try getAttr(PartialIV()) as? String else {
                throw CoseError.invalidIV("Partial IV not found while baseIV is present")
            }
            
            // Perform the XOR operation between PartialIV and BaseIV
            let partialIVInt = partialIV.hexStringToData.reduce(0) {
                ($0 << 8) | Int($1)
            }
            let baseIVInt = baseIV.reduce(0) { ($0 << 8) | Int($1) }
            let combinedInt = partialIVInt ^ baseIVInt
            
            // Convert the resulting integer back into bytes
            let combinedBytes = withUnsafeBytes(of: combinedInt.bigEndian) { Data($0) }
            return combinedBytes
        }
        
        if nonce == nil, let baseIV = self.key?.baseIV, baseIV.isEmpty {
            throw CoseError.invalidIV("No IV found")
        }
        
        return nonce!
    }
}
