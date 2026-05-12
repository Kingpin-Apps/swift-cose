import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import SwiftCurve448

/// EdDSA
public class EdDSAAlgorithm: CoseAlgorithm {
    public init() {
        super.init(identifier: .edDSA, fullname: "EDDSA")
    }
    
    public func sign(key: OKPKey, data: Data) throws -> Data {
        let curveId = CoseCurveIdentifier(rawValue: key.curve.identifier!)
        switch curveId {
            case .ed25519:
                guard let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: key.d!) else {
                    throw CoseError.invalidKey("Invalid private key")
                }
                return try privateKey.signature(for: data)
                
            case .ed448:
                guard let privateKey = try? Curve448.Signing.PrivateKey(rawRepresentation: key.d!) else {
                    throw CoseError.invalidKey("Invalid private key")
                }
                return try privateKey.signature(for: data)
                
            default:
                throw CoseError.invalidCurve("Unsupported curve")
        }
    }

    public func verify(key: OKPKey, data: Data, signature: Data) throws -> Bool {
        let curveId = CoseCurveIdentifier(rawValue: key.curve.identifier!)
        switch curveId {
            case .ed25519:
                guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: key.x!) else {
                    throw CoseError.invalidKey("Error creating public key for \(curveId.debugDescription)")
                }
                return publicKey.isValidSignature(signature, for: data)
                
            case .ed448:
                guard let publicKey = try? Curve448.Signing.PublicKey(rawRepresentation: key.x!) else {
                    throw CoseError.invalidKey("Error creating public key for \(curveId.debugDescription)")
                }
                return publicKey.isValidSignature(signature, for: data)
                
            default:
                return false
        }
    }
}
