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

    /// The Ed448 group order L, little-endian (RFC 8032 section 5.2).
    static let ed448Order: [UInt8] = [
        0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
        0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c,
    ] + [UInt8](repeating: 0xff, count: 27) + [0x3f, 0x00]

    /// RFC 8032 section 5.2.7: S (the last 57 bytes) must be less than L.
    /// The Ed448 backend reduces S mod L, so S + kL would also verify.
    static func ed448ScalarIsCanonical(_ signature: Data) -> Bool {
        guard signature.count == 114 else { return false }
        let s = Array(signature.suffix(57))
        for i in stride(from: 56, through: 0, by: -1) {
            if s[i] < ed448Order[i] { return true }
            if s[i] > ed448Order[i] { return false }
        }
        return false // S == L
    }

    public func verify(key: OKPKey, data: Data, signature: Data) throws -> Bool {
        guard let curveIdentifier = key.curve.identifier else {
            throw CoseError.invalidCurve("OKP key has no curve")
        }
        guard let x = key.x, !x.isEmpty else {
            throw CoseError.invalidKey("An OKP public key needs x")
        }
        let curveId = CoseCurveIdentifier(rawValue: curveIdentifier)
        switch curveId {
            case .ed25519:
                guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: x) else {
                    throw CoseError.invalidKey("Error creating public key for \(curveId.debugDescription)")
                }
                return publicKey.isValidSignature(signature, for: data)
                
            case .ed448:
                guard Self.ed448ScalarIsCanonical(signature) else { return false }
                guard let publicKey = try? Curve448.Signing.PublicKey(rawRepresentation: x) else {
                    throw CoseError.invalidKey("Error creating public key for \(curveId.debugDescription)")
                }
                return publicKey.isValidSignature(signature, for: data)
                
            default:
                return false
        }
    }
}
