import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import UncommonCrypto

/// Base class for ECDSA algorithms
public class EcdsaAlgorithm: CoseAlgorithm {
    /// Signs the data
    /// - Parameters:
    ///   - key: The EC2 key to use for signing
    ///   - data: The data to sign
    /// - Returns: The signature
    public func sign(key: EC2Key, data: Data) throws -> Data {
        let signature: Data
        switch CoseAlgorithmIdentifier(rawValue: identifier!) {
            case .es256:
                guard let privateKey = try? P256.Signing.PrivateKey(rawRepresentation: key.d!) else {
                    throw CoseError.invalidKey("Invalid private key")
                }
                signature = try privateKey.signature(for: data).derRepresentation
            case .es384:
                guard let privateKey = try? P384.Signing.PrivateKey(rawRepresentation: key.d!) else {
                    throw CoseError.invalidKey("Invalid private key")
                }
                signature = try privateKey.signature(for: data).derRepresentation
            case .es512:
                guard let privateKey = try? P521.Signing.PrivateKey(rawRepresentation: key.d!) else {
                    throw CoseError.invalidKey("Invalid private key")
                }

                signature = try privateKey.signature(for: data).derRepresentation
            default:
                throw CoseError.invalidAlgorithm("Unsupported algorithm")
        }
        return signature
    }
    
    
    /// Verify the signature
    /// - Parameters:
    ///   - key: The EC2 key to use for verification
    ///   - data: The data to
    ///   - signature: The signature
    /// - Returns: True if the signature is valid
    public func verify(key: EC2Key, data: Data, signature: Data) throws -> Bool {
        // Create x963Representation: a prefix of 0x04 followed by x and y concatenated
        var x963Representation = Data([0x04])
        x963Representation.append(key.x!)
        x963Representation.append(key.y!)
        
        var isValid: Bool = false
        let algId = CoseAlgorithmIdentifier(rawValue: identifier!)
        switch algId {
            case .es256:
                guard let publicKey = try? P256.Signing.PublicKey(x963Representation: x963Representation) else {
                    throw CoseError.invalidKey("Error creating public key for \(algId.debugDescription)")
                }
                
                do {
                    let sig = try P256.Signing.ECDSASignature(derRepresentation: signature)
                    isValid = publicKey.isValidSignature(sig, for: SHA256.hash(data: data))
                } catch {
                    throw CoseError.genericError("Error verifying signature. \(error.localizedDescription)")
                }
            case .es384:
                guard let publicKey = try? P384.Signing.PublicKey(x963Representation: x963Representation) else {
                    throw CoseError.invalidKey("Error creating public key for \(algId.debugDescription)")
                }
                
                do {
                    let sig = try P384.Signing.ECDSASignature(derRepresentation: signature)
                    isValid = publicKey.isValidSignature(sig, for: SHA384.hash(data: data))
                } catch {
                    throw CoseError.genericError("Error verifying signature. \(error.localizedDescription)")
                }
            case .es512:
                guard let publicKey = try? P521.Signing.PublicKey(x963Representation: x963Representation) else {
                    throw CoseError.invalidKey("Error creating public key for \(algId.debugDescription)")
                }
                
                do {
                    let sig = try P521.Signing.ECDSASignature(derRepresentation: signature)
                    isValid = publicKey.isValidSignature(sig, for: SHA384.hash(data: data))
                    isValid = publicKey
                        .isValidSignature(
                            try P521.Signing
                                .ECDSASignature(derRepresentation: signature),
                            for: SHA512.hash(data: data)
                        )
                } catch {
                    throw CoseError.genericError("Error verifying signature. \(error.localizedDescription)")
                }
            default:
                throw CoseError.invalidAlgorithm("Unsupported algorithm")
        }
        return isValid
    }
}

public class Es256: EcdsaAlgorithm {
    public init() {
        super.init(identifier: .es256, fullname: "ES256")
    }
}


public class Es384: EcdsaAlgorithm {
    public init() {
        super.init(identifier: .es384, fullname: "ES384")
    }
}

public class Es512: EcdsaAlgorithm {
    public init() {
        super.init(identifier: .es512, fullname: "ES512")
    }
}
