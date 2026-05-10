import Foundation
import CryptoKit
import P256K
import CryptoSwift
import SwiftCurve448


public func derivePublicKeyFromNumbers<T>(curve: CurveType, x: Data, y: Data) throws -> T {
    var x963Representation = Data([0x04])
    x963Representation.append(x)
    x963Representation.append(y)
    
    do {
        switch curve {
            case .SECP256K1:
                return try P256K.KeyAgreement.PublicKey(x963Representation: x963Representation) as! T
            case .SECP256R1:
                return try P256.KeyAgreement.PublicKey(x963Representation: x963Representation) as! T
            case .SECP384R1:
                return try P384.KeyAgreement.PublicKey(x963Representation: x963Representation) as! T
            case .SECP521R1:
                return try P521.KeyAgreement.PublicKey(x963Representation: x963Representation) as! T
            default:
                throw CoseError.invalidAlgorithm("Unsupported curve")
        }
    } catch {
        let error = error as! CryptoKit.CryptoKitError
        throw CoseError.invalidKey(
            "Error deriving public key for \(curve): \(error.localizedDescription)."
        )
    }
}

public func getXY(from key: Any) throws -> (x: Data, y: Data?) {
    var x: Data?
    var y: Data?
    
    if let privateKey = key as? P256K.KeyAgreement.PrivateKey {
        let keyData = privateKey.publicKey.uncompressedRepresentation.dropFirst()
        x = keyData.prefix(32)
        y = keyData.suffix(32)
    } else if let privateKey = key as? P256K.Signing.PrivateKey {
        let keyData = privateKey.publicKey.uncompressedRepresentation.dropFirst()
        x = keyData.prefix(32)
        y = keyData.suffix(32)
    }
    else if let privateKey = key as? P256.KeyAgreement.PrivateKey {
        let keyData = privateKey.publicKey.x963Representation.dropFirst()
        x = keyData.prefix(32) 
        y = keyData.suffix(32)
    } else if let privateKey = key as? P256.Signing.PrivateKey {
        let keyData = privateKey.publicKey.x963Representation.dropFirst()
        x = keyData.prefix(32) 
        y = keyData.suffix(32)
    }
    else if let privateKey = key as? P384.KeyAgreement.PrivateKey {
        let keyData = privateKey.publicKey.x963Representation.dropFirst()
        x = keyData.prefix(48)
        y = keyData.suffix(48)
    } else if let privateKey = key as? P384.Signing.PrivateKey {
        let keyData = privateKey.publicKey.x963Representation.dropFirst()
        x = keyData.prefix(48)
        y = keyData.suffix(48)
    }
    else if let privateKey = key as? P521.KeyAgreement.PrivateKey {
        x = privateKey.publicKey.x963Representation.subdata(in: 1..<67)
        y = privateKey.publicKey.x963Representation.subdata(in: 67..<133)
    } else if let privateKey = key as? P521.Signing.PrivateKey {
        x = privateKey.publicKey.x963Representation.subdata(in: 1..<67)
        y = privateKey.publicKey.x963Representation.subdata(in: 67..<133)
    }
    else if let privateKey = key as? Curve448.KeyAgreement.PrivateKey {
        x = privateKey.publicKey.rawRepresentation
    } else if let privateKey = key as? Curve448.Signing.PrivateKey {
        x = privateKey.publicKey.rawRepresentation
    }
    else if let privateKey = key as? Curve25519.KeyAgreement.PrivateKey {
        x = privateKey.publicKey.rawRepresentation
    } else if let privateKey = key as? Curve25519.Signing.PrivateKey {
        x = privateKey.publicKey.rawRepresentation
    }
    else if let publicKey = key as? P256K.KeyAgreement.PublicKey {
        let keyData = publicKey.uncompressedRepresentation.dropFirst()
        x = keyData.prefix(32)
        y = keyData.suffix(32)
    } else if let publicKey = key as? P256K.Signing.PublicKey {
        let keyData = publicKey.uncompressedRepresentation.dropFirst()
        x = keyData.prefix(32)
        y = keyData.suffix(32)
    }
    else if let publicKey = key as? P256.KeyAgreement.PublicKey {
        let keyData = publicKey.x963Representation.dropFirst()
        x = keyData.prefix(32)
        y = keyData.suffix(32)
    } else if let publicKey = key as? P256.Signing.PublicKey {
        let keyData = publicKey.x963Representation.dropFirst()
        x = keyData.prefix(32)
        y = keyData.suffix(32)
    }
    else if let publicKey = key as? P384.KeyAgreement.PublicKey {
        let keyData = publicKey.x963Representation.dropFirst()
        x = keyData.prefix(48)
        y = keyData.suffix(48)
    } else if let publicKey = key as? P384.Signing.PublicKey {
        let keyData = publicKey.x963Representation.dropFirst()
        x = keyData.prefix(48)
        y = keyData.suffix(48)
    }
    else if let publicKey = key as? P521.KeyAgreement.PublicKey {
        x = publicKey.x963Representation.subdata(in: 1..<67)
        y = publicKey.x963Representation.subdata(in: 67..<133)
    } else if let publicKey = key as? P521.Signing.PublicKey {
        x = publicKey.x963Representation.subdata(in: 1..<67)
        y = publicKey.x963Representation.subdata(in: 67..<133)
    }
    else if let publicKey = key as? Curve448.KeyAgreement.PublicKey {
        x = publicKey.rawRepresentation
    } else if let publicKey = key as? Curve448.Signing.PublicKey {
        x = publicKey.rawRepresentation
    }
    else if let publicKey = key as? Curve25519.KeyAgreement.PublicKey {
        x = publicKey.rawRepresentation
    } else if let publicKey = key as? Curve25519.Signing.PublicKey {
        x = publicKey.rawRepresentation
    }
    else {
        throw CoseError.invalidKey("Unsupported key type: \(type(of: key))")
    }
    return (x!, y)
    
}

public func deriveNumbers(from key: Any) throws -> (curve: CurveType, x: Data, y: Data?, d: Data?) {
    
    var x: Data?
    var y: Data?
    var d: Data?
    var curve: CurveType?
    
    if let privateKey = key as? P256K.KeyAgreement.PrivateKey {
        curve = .SECP256K1
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    } else if let privateKey = key as? P256K.Signing.PrivateKey {
        // Fix from prior K1-based version: this branch is secp256k1 (the underlying curve of
        // both K1 and P256K's Signing namespace), not secp256r1.
        curve = .SECP256K1
        (x, y) = try getXY(from: privateKey)
        d = privateKey.dataRepresentation
    }
    else if let privateKey = key as? P256.KeyAgreement.PrivateKey {
        curve = .SECP256R1
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    } else if let privateKey = key as? P256.Signing.PrivateKey {
        curve = .SECP256R1
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    }
    else if let privateKey = key as? P384.KeyAgreement.PrivateKey {
        curve = .SECP384R1
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    } else if let privateKey = key as? P384.Signing.PrivateKey {
        curve = .SECP384R1
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    }
    else if let privateKey = key as? P521.KeyAgreement.PrivateKey {
        curve = .SECP521R1
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    } else if let privateKey = key as? P521.Signing.PrivateKey {
        curve = .SECP521R1
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    }
    else if let privateKey = key as? Curve448.KeyAgreement.PrivateKey {
        curve = .X448
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    } else if let privateKey = key as? Curve448.Signing.PrivateKey {
        curve = .ED448
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    }
    else if let privateKey = key as? Curve25519.KeyAgreement.PrivateKey {
        curve = .X25519
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    } else if let privateKey = key as? Curve25519.Signing.PrivateKey {
        curve = .ED25519
        (x, y) = try getXY(from: privateKey)
        d = privateKey.rawRepresentation
    }
    else if let publicKey = key as? P256K.KeyAgreement.PublicKey {
        curve = .SECP256K1
        (x, y) = try getXY(from: publicKey)
    } else if let publicKey = key as? P256K.Signing.PublicKey {
        curve = .SECP256K1
        (x, y) = try getXY(from: publicKey)
    }
    else if let publicKey = key as? P256.KeyAgreement.PublicKey {
        curve = .SECP256R1
        (x, y) = try getXY(from: publicKey)
    } else if let publicKey = key as? P256.Signing.PublicKey {
        curve = .SECP256R1
        (x, y) = try getXY(from: publicKey)
    }
    else if let publicKey = key as? P384.KeyAgreement.PublicKey {
        curve = .SECP384R1
        (x, y) = try getXY(from: publicKey)
    } else if let publicKey = key as? P384.Signing.PublicKey {
        curve = .SECP384R1
        (x, y) = try getXY(from: publicKey)
    }
    else if let publicKey = key as? P521.KeyAgreement.PublicKey {
        curve = .SECP521R1
        (x, y) = try getXY(from: publicKey)
    } else if let publicKey = key as? P521.Signing.PublicKey {
        curve = .SECP521R1
        (x, y) = try getXY(from: publicKey)
    }
    else if let publicKey = key as? Curve448.KeyAgreement.PublicKey {
        curve = .X448
        (x, y) = try getXY(from: publicKey)
    } else if let publicKey = key as? Curve448.Signing.PublicKey {
        curve = .ED448
        (x, y) = try getXY(from: publicKey)
    }
    else if let publicKey = key as? Curve25519.KeyAgreement.PublicKey {
        curve = .X25519
        (x, y) = try getXY(from: publicKey)
    } else if let publicKey = key as? Curve25519.Signing.PublicKey {
        curve = .ED25519
        (x, y) = try getXY(from: publicKey)
    }
    else {
        throw CoseError.invalidKey("Unsupported key type: \(type(of: key))")
    }
    return (curve!, x!, y, d)
}

public func deriveKeyAgreementPublicNumbersCompact(from d: Data, curve: CurveType) throws -> (Data, Data?) {
    
    var x: Data?
    var y: Data?
    
    switch curve {
        case .SECP256K1:
            let publicKey: P256K.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: publicKey)
        case .SECP256R1:
            let publicKey: P256.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: publicKey)
        case .SECP384R1:
            let publicKey: P384.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: publicKey)
        case .SECP521R1:
            let publicKey: P521.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: publicKey)
        case .X25519:
            let publicKey: Curve25519.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
                from: d,
                curve: curve
            )
            x = publicKey.rawRepresentation
        case .X448:
            let publicKey: Curve448.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
                from: d,
                curve: curve
            )
            x = publicKey.rawRepresentation
        default:
            throw CoseError.invalidCurve("Invalid curve for key agreement: \(curve)")
    }
    
    return (x!, y)
}

public func deriveSigningPublicNumbersCompact(from d: Data, curve: CurveType) throws -> (Data, Data?) {
    
    var x: Data?
    var y: Data?
    
    switch curve {
        case .SECP256K1:
            let publicKey: P256K.Signing.PublicKey = try deriveSigningPublicKeyCompact(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: publicKey)
        case .SECP256R1:
            let publicKey: P256.Signing.PublicKey = try deriveSigningPublicKeyCompact(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: publicKey)
        case .SECP384R1:
            let publicKey: P384.Signing.PublicKey = try deriveSigningPublicKeyCompact(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: publicKey)
        case .SECP521R1:
            let publicKey: P521.Signing.PublicKey = try deriveSigningPublicKeyCompact(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: publicKey)
        case .ED25519:
            let publicKey: Curve25519.Signing.PublicKey = try deriveSigningPublicKeyCompact(
                from: d,
                curve: curve
            )
            x = publicKey.rawRepresentation
        case .ED448:
            let publicKey: Curve448.Signing.PublicKey = try deriveSigningPublicKeyCompact(
                from: d,
                curve: curve
            )
            x = publicKey.rawRepresentation
        default:
            throw CoseError.invalidCurve("Invalid curve for signing: \(curve)")
    }
    
    return (x!, y)
}

public func deriveKeyAgreementPublicNumbers(from d: Data, curve: CurveType) throws -> (Data, Data?) {
    
    var x: Data?
    var y: Data?
    
    switch curve {
        case .SECP256K1:
            let privateKey: P256K.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: privateKey)
        case .SECP256R1:
            let privateKey: P256.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: privateKey)
        case .SECP384R1:
            let privateKey: P384.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: privateKey)
        case .SECP521R1:
            let privateKey: P521.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: privateKey)
        case .X25519:
            let privateKey: Curve25519.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
                from: d,
                curve: curve
            )
            x = privateKey.publicKey.rawRepresentation
        case .X448:
            let privateKey: Curve448.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
                from: d,
                curve: curve
            )
            x = privateKey.publicKey.rawRepresentation
        default:
            throw CoseError.invalidCurve("Invalid curve for key agreement: \(curve)")
    }
    
    return (x!, y)
}

public func deriveSigningPublicNumbers(from d: Data, curve: CurveType) throws -> (Data, Data?) {
    
    var x: Data?
    var y: Data?
    
    switch curve {
        case .SECP256K1:
            let privateKey: P256K.Signing.PrivateKey = try deriveSigningPrivateKey(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: privateKey)
        case .SECP256R1:
            let privateKey: P256.Signing.PrivateKey = try deriveSigningPrivateKey(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: privateKey)
        case .SECP384R1:
            let privateKey: P384.Signing.PrivateKey = try deriveSigningPrivateKey(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: privateKey)
        case .SECP521R1:
            let privateKey: P521.Signing.PrivateKey = try deriveSigningPrivateKey(
                from: d,
                curve: curve
            )
            (x, y) = try getXY(from: privateKey)
        case .ED25519:
            let privateKey: Curve25519.Signing.PrivateKey = try deriveSigningPrivateKey(
                from: d,
                curve: curve
            )
            x = privateKey.publicKey.rawRepresentation
        case .ED448:
            let privateKey: Curve448.Signing.PrivateKey = try deriveSigningPrivateKey(
                from: d,
                curve: curve
            )
            x = privateKey.publicKey.rawRepresentation
        default:
            throw CoseError.invalidCurve("Invalid curve for signing: \(curve)")
    }
    
    return (x!, y)
}

public func deriveKeyAgreementPrivateKey<T>(from key: Data, curve: CurveType) throws -> T {
    do {
        switch curve {
            case .SECP256K1:
                return try! P256K.KeyAgreement.PrivateKey(dataRepresentation: key) as! T
            case .SECP256R1:
                return try! P256.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
            case .SECP384R1:
                return try! P384.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
            case .SECP521R1:
                return try! P521.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
            case .X25519:
                return try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
            case .X448:
                return try! Curve448.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
            default:
                throw CoseError.invalidCurve("Invalid curve for key agreement: \(curve)")
        }
    } catch {
        throw CoseError.invalidKey(
            "Error deriving private key for \(curve): \(error.localizedDescription)"
        )
    }
}

public func deriveSigningPrivateKey<T>(from key: Data, curve: CurveType) throws -> T {
    do {
        switch curve {
            case .SECP256K1:
                return try! P256K.Signing.PrivateKey(dataRepresentation: key) as! T
            case .SECP256R1:
                return try! P256.Signing.PrivateKey(rawRepresentation: key) as! T
            case .SECP384R1:
                return try! P384.Signing.PrivateKey(rawRepresentation: key) as! T
            case .SECP521R1:
                return try! P521.Signing.PrivateKey(rawRepresentation: key) as! T
            case .ED25519:
                return try! Curve25519.Signing.PrivateKey(rawRepresentation: key) as! T
            case .ED448:
                return try! Curve448.Signing.PrivateKey(rawRepresentation: key) as! T
            default:
                throw CoseError.invalidCurve("Invalid curve for key agreement: \(curve)")
        }
    } catch {
        throw CoseError.invalidKey(
            "Error deriving private key for \(curve): \(error.localizedDescription)"
        )
    }
}

public func deriveKeyAgreementPublicKeyCompact<T>(from key: Data, curve: CurveType) throws -> T {
    do {
        switch curve {
            case .SECP256K1:
                return try P256K.KeyAgreement.PublicKey(dataRepresentation: key, format: .compressed) as! T
            case .SECP256R1:
                return try P256.KeyAgreement.PublicKey(compressedRepresentation: key) as! T
            case .SECP384R1:
                return try P384.KeyAgreement.PublicKey(compressedRepresentation: key) as! T
            case .SECP521R1:
                return try P521.KeyAgreement.PublicKey(compressedRepresentation: key) as! T
            case .X25519:
                return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: key) as! T
            case .X448:
                return try Curve448.KeyAgreement.PublicKey(rawRepresentation: key) as! T
            default:
                throw CoseError.invalidCurve("Invalid curve for key agreement: \(curve)")
        }
    }
    catch {
        throw CoseError.invalidKey(
            "Error deriving key agreement for \(curve) public key: \(error.localizedDescription)"
        )
    }
    
}

public func deriveSigningPublicKeyCompact<T>(from key: Data, curve: CurveType) throws -> T {
    do  {
        switch curve {
            case .SECP256K1:
                return try P256K.Signing.PublicKey(dataRepresentation: key, format: .compressed) as! T
            case .SECP256R1:
                return try P256.Signing.PublicKey(compressedRepresentation: key) as! T
            case .SECP384R1:
                return try P384.Signing.PublicKey(compressedRepresentation: key) as! T
            case .SECP521R1:
                return try P521.Signing.PublicKey(compressedRepresentation: key) as! T
            case .ED25519:
                return try Curve25519.Signing.PublicKey(rawRepresentation: key) as! T
            case .ED448:
                return try Curve448.Signing.PublicKey(rawRepresentation: key) as! T
            default:
                throw CoseError.invalidCurve("Invalid curve for signing: \(curve)")
        }
    } catch {
        throw CoseError.invalidKey(
            "Error deriving public key for \(curve): \(error.localizedDescription)"
        )
    }
}

public func generateKeyAgreementPrivateKey<T>(curve: CurveType) throws -> T {
    switch curve {
        case .SECP256K1:
            return try P256K.KeyAgreement.PrivateKey() as! T
        case .SECP256R1:
            return P256.KeyAgreement.PrivateKey() as! T
        case .SECP384R1:
            return P384.KeyAgreement.PrivateKey() as! T
        case .SECP521R1:
            return P521.KeyAgreement.PrivateKey() as! T
        case .X25519:
            return Curve25519.KeyAgreement.PrivateKey() as! T
        case .X448:
            return Curve448.KeyAgreement.PrivateKey() as! T
        default:
            throw CoseError.invalidCurve("Invalid curve for key agreement: \(curve)")
    }
}

public func generateSigningPrivateKey<T>(curve: CurveType) throws -> T {
    switch curve {
        case .SECP256K1:
            return try P256K.Signing.PrivateKey() as! T
        case .SECP256R1:
            return P256.Signing.PrivateKey() as! T
        case .SECP384R1:
            return P384.Signing.PrivateKey() as! T
        case .SECP521R1:
            return P521.Signing.PrivateKey() as! T
        case .ED25519:
            return Curve25519.Signing.PrivateKey() as! T
        case .ED448:
            return Curve448.Signing.PrivateKey() as! T
        default:
            throw CoseError.invalidCurve("Invalid curve for signing: \(curve)")
    }
}
