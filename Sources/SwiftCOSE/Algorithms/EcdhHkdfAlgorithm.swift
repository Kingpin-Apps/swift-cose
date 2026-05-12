#if canImport(CryptoKit)
import CryptoKit
private typealias HashSHA256 = CryptoKit.SHA256
private typealias HashSHA512 = CryptoKit.SHA512
#else
import Crypto
private typealias HashSHA256 = Crypto.SHA256
private typealias HashSHA512 = Crypto.SHA512
#endif
import Foundation
import P256K

public class EcdhHkdfAlgorithm: CoseAlgorithm {
    public var hashFunction: CoseHashFunction
    public var keyWrapFunction: CoseAlgorithm

    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        hashFunction: CoseHashFunction,
        keyWrapFunction: CoseAlgorithm
    ) {
        self.hashFunction = hashFunction
        self.keyWrapFunction = keyWrapFunction
        super.init(identifier: identifier, fullname: fullname)
    }

    private func ecdh(curve: CoseCurve, privateKey: EC2Key?, publicKey: EC2Key?) throws -> Data {
        guard let dValue = privateKey?.d else {
            throw CoseError.invalidKey("Missing private key component d")
        }
        guard let xValue = publicKey?.x, let yValue = publicKey?.y else {
            throw CoseError.invalidKey("Missing public key components x or y")
        }

        var x963Representation = Data([0x04])
        x963Representation.append(xValue)
        x963Representation.append(yValue)

        switch curve.curveType {
        case .SECP256K1:
            let privateKeyData = try P256K.KeyAgreement.PrivateKey(
                dataRepresentation: dValue
            )
            let publicKeyData = try P256K.KeyAgreement.PublicKey(
                x963Representation: x963Representation)

            let sharedSecret = privateKeyData.sharedSecretFromKeyAgreement(
                with: publicKeyData
            )
            return sharedSecret.withUnsafeBytes { Data($0) }
        case .SECP256R1:
            let privateKeyData = try P256.KeyAgreement.PrivateKey(
                rawRepresentation: dValue
            )
            let publicKeyData = try P256.KeyAgreement.PublicKey(
                x963Representation: x963Representation)

            let sharedSecret = try privateKeyData.sharedSecretFromKeyAgreement(
                with: publicKeyData
            )
            return sharedSecret.withUnsafeBytes { Data($0) }
        case .SECP384R1:
            let privateKeyData = try P384.KeyAgreement.PrivateKey(
                rawRepresentation: dValue
            )
            let publicKeyData = try P384.KeyAgreement.PublicKey(
                x963Representation: x963Representation)

            let sharedSecret = try privateKeyData.sharedSecretFromKeyAgreement(
                with: publicKeyData
            )
            return sharedSecret.withUnsafeBytes { Data($0) }
        case .SECP521R1:
            let privateKeyData = try P521.KeyAgreement.PrivateKey(
                rawRepresentation: dValue
            )
            let publicKeyData = try P521.KeyAgreement.PublicKey(
                x963Representation: x963Representation)

            let sharedSecret = try privateKeyData.sharedSecretFromKeyAgreement(
                with: publicKeyData
            )
            return sharedSecret.withUnsafeBytes { Data($0) }
        default:
            throw CoseError.invalidAlgorithm("Unsupported curve")
        }
    }

    public func deriveKEK(
        curve: CoseCurve, privateKey: EC2Key, publicKey: EC2Key, context: CoseKDFContext
    ) throws -> Data {
        let sharedSecret = try ecdh(curve: curve, privateKey: privateKey, publicKey: publicKey)
        let hkdf: SymmetricKey

        switch self.hashFunction {
        case .sha256:
            hkdf = HKDF<HashSHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: sharedSecret),
                info: try context.encode(),
                outputByteCount: context.suppPubInfo.keyDataLength
            )
        case .sha512:
            hkdf = HKDF<HashSHA512>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: sharedSecret),
                info: try context.encode(),
                outputByteCount: context.suppPubInfo.keyDataLength
            )
        default:
            throw CoseError.invalidAlgorithm("Unsupported hash function")
        }
        return hkdf.withUnsafeBytes { Data($0) }
    }
}

/// ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
class EcdhEsA128KW: EcdhHkdfAlgorithm {
    public init() {
        super.init(
            identifier: .ecdhES_A128KW,
            fullname: "ECDH_ES_A128KW",
            hashFunction: .sha256,
            keyWrapFunction: A128KW()
        )
    }
}

/// ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
class EcdhEsA192KW: EcdhHkdfAlgorithm {
    public init() {
        super.init(
            identifier: .ecdhES_A192KW,
            fullname: "ECDH_ES_A192KW",
            hashFunction: .sha256,
            keyWrapFunction: A192KW()
        )
    }
}

/// ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
class EcdhEsA256KW: EcdhHkdfAlgorithm {
    public init() {
        super.init(
            identifier: .ecdhES_A256KW,
            fullname: "ECDH_ES_A256KW",
            hashFunction: .sha256,
            keyWrapFunction: A256KW()
        )
    }
}

/// ECDH ES w/ HKDF - generate key directly (256-bit hash)
class EcdhEsHKDF256: EcdhHkdfAlgorithm {
    public init() {
        super.init(
            identifier: .ecdhES_HKDF_256,
            fullname: "ECDH_ES_HKDF_256",
            hashFunction: .sha256,
            keyWrapFunction: Direct()
        )
    }
}

/// ECDH ES w/ HKDF - generate key directly (512-bit hash)
class EcdhEsHKDF512: EcdhHkdfAlgorithm {
    public init() {
        super.init(
            identifier: .ecdhES_HKDF_512,
            fullname: "ECDH_ES_HKDF_512",
            hashFunction: .sha512,
            keyWrapFunction: Direct()
        )
    }
}

/// ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key
class EcdhSsA128KW: EcdhHkdfAlgorithm {
    public init() {
        super.init(
            identifier: .ecdhSS_A128KW,
            fullname: "ECDH_SS_A128KW",
            hashFunction: .sha256,
            keyWrapFunction: A128KW()
        )
    }
}

/// ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key
class EcdhSsA192KW: EcdhHkdfAlgorithm {
    public init() {
        super.init(
            identifier: .ecdhSS_A192KW,
            fullname: "ECDH_SS_A192KW",
            hashFunction: .sha256,
            keyWrapFunction: A192KW()
        )
    }
}

/// ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key
class EcdhSsA256KW: EcdhHkdfAlgorithm {
    public init() {
        super.init(
            identifier: .ecdhSS_A256KW,
            fullname: "ECDH_SS_A256KW",
            hashFunction: .sha256,
            keyWrapFunction: A256KW()
        )
    }
}

/// ECDH SS w/ HKDF - generate key directly (256-bit hash)
class EcdhSsHKDF256: EcdhHkdfAlgorithm {
    public init() {
        super.init(
            identifier: .ecdhSS_HKDF_256,
            fullname: "ECDH_SS_HKDF_256",
            hashFunction: .sha256,
            keyWrapFunction: Direct()
        )
    }
}

/// ECDH SS w/ HKDF - generate key directly (512-bit hash)
class EcdhSsHKDF512: EcdhHkdfAlgorithm {
    public init() {
        super.init(
            identifier: .ecdhSS_HKDF_512,
            fullname: "ECDH_SS_HKDF_512",
            hashFunction: .sha512,
            keyWrapFunction: Direct()
        )
    }
}
