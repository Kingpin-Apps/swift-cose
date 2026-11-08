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
            try baseStructure(&structure)
            return try CBORSerialization.data(from: .array(structure))
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
        
        guard let payload = self.payload else {
            throw CoseError.valueError("No ciphertext to decrypt")
        }
        
        try key
            .verify(
                keyType: CoseSymmetricKey.self,
                algorithm: alg,
                keyOps: [DecryptOp()]
            )
        guard let symmetricKey = key as? CoseSymmetricKey else {
            throw CoseError.invalidKey("Key must be of type SymmetricKey.")
        }
        
        if let alg = alg as? AesCcmAlgorithm {
            return try alg
                .decrypt(
                    key: symmetricKey,
                    nonce: nonce,
                    ciphertext: payload,
                    aad: encStructure
                )
        } else if let alg = alg as? AesGcmAlgorithm {
            return try alg
                .decrypt(
                    key: symmetricKey,
                    nonce: nonce,
                    ciphertext: payload,
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
        
        guard let payload = self.payload else {
            throw CoseError.valueError("No payload to encrypt")
        }
        
        try key
            .verify(
                keyType: CoseSymmetricKey.self,
                algorithm: alg,
                keyOps: [EncryptOp()]
            )
        guard let symmetricKey = key as? CoseSymmetricKey else {
            throw CoseError.invalidKey("Key must be of type SymmetricKey.")
        }
        
        if let alg = alg as? AesCcmAlgorithm {
            return try alg
                .encrypt(
                    key: symmetricKey,
                    nonce: nonce,
                    data: payload,
                    aad: encStructure
                )
        } else if let alg = alg as? AesGcmAlgorithm {
            return try alg
                .encrypt(
                    key: symmetricKey,
                    nonce: nonce,
                    data: payload,
                    aad: encStructure
                )
        } else {
            throw CoseError.invalidAlgorithm("Unsupported algorithm")
        }
    }

    private func getNonce() throws -> Data {
        // A full IV in the headers wins.
        if let nonce = (try? getAttr(IV())) as? Data {
            return nonce
        }
        
        // RFC 9052, section 3.1: otherwise left-pad the Partial IV to the
        // length of the key's Base IV and XOR the two.
        guard let baseIV = self.key?.baseIV, !baseIV.isEmpty else {
            throw CoseError.invalidIV("No IV found")
        }
        guard let partialIV = (try? getAttr(PartialIV())) as? Data else {
            throw CoseError.invalidIV("Partial IV not found while baseIV is present")
        }
        guard partialIV.count <= baseIV.count else {
            throw CoseError.invalidIV("Partial IV is longer than the Base IV")
        }
        
        let padded = Data(count: baseIV.count - partialIV.count) + partialIV
        return Data(zip(padded, baseIV).map { $0 ^ $1 })
    }
}
