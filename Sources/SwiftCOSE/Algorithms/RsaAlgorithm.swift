import Foundation
#if canImport(CryptoKit)
import CryptoKit
private typealias CKDigest = CryptoKit.Digest
#else
import Crypto
private typealias CKDigest = Crypto.Digest
#endif
import BigInt
import CryptoSwift
import _CryptoExtras

/// The public numbers of an RSA key, after checking its size.
private func publicParts(of key: RSAKey) throws -> (n: Data, e: Data) {
    try key.requireSupportedSize()
    guard let n = key.n, let e = key.e else {
        throw CoseError.invalidKey("RSA public key needs n and e")
    }
    return (n, e)
}

/// The private numbers of an RSA key, after checking its size.
private func privateParts(of key: RSAKey) throws -> (n: Data, e: Data, d: Data, p: Data, q: Data) {
    let (n, e) = try publicParts(of: key)
    guard let d = key.d, let p = key.p, let q = key.q else {
        throw CoseError.invalidKey("RSA private key needs n, e, d, p and q")
    }
    return (n, e, d, p, q)
}

public enum Padding {
    case oaep
    case pkcs1v1_5
    case pss
    case pssZero
}

/// RSA signing and (key-wrap) encryption.
public class RsaAlgorithm: CoseAlgorithm {
    public var hashFunction: CoseHashFunction
    
    public var padding: Padding {
        fatalError("Must be implemented by subclasses")
    }
    
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        hashFunction: CoseHashFunction
    ) {
        self.hashFunction = hashFunction
        super.init(identifier: identifier, fullname: fullname)
    }
    
    public func sign(key: RSAKey, data: Data) throws -> Data {
        // Construct the private key
        let parts = try privateParts(of: key)
        let privateKey: _RSA.Signing.PrivateKey
        do{
            privateKey =  try _RSA.Signing.PrivateKey(
                n: parts.n, e: parts.e, d: parts.d, p: parts.p, q: parts.q
            )
        } catch {
            throw CoseError.valueError("Invalid RSA key: \(error.localizedDescription)")
        }
        
        // Get hash of data
        let digest: any CKDigest
        switch hashFunction {
            case .sha1:
                digest = Insecure.SHA1.hash(data: data)
            case .sha256:
                digest = SHA256.hash(data: data)
            case .sha384:
                digest = SHA384.hash(data: data)
            case .sha512:
                digest = SHA512.hash(data: data)
        }
        
        // Sign the data
        switch padding {
            case .pkcs1v1_5:
                return try privateKey
                    .signature(
                        for: digest,
                        padding: .insecurePKCS1v1_5
                    ).rawRepresentation
            case .pss:
                return try privateKey.signature(for: digest, padding: .PSS).rawRepresentation
            default:
                throw CoseError.valueError("Unsupported padding")
        }
    }
        
    public func verify(key: RSAKey, data: Data, signature: Data)throws  -> Bool {
        // A key that is too small is a usage error, not a bad signature.
        let parts = try publicParts(of: key)
        do {
            // Construct the public key
            let rsaPublicKey = try _RSA.Signing.PublicKey(n: parts.n, e: parts.e)
            
            // Get hash of data
            let digest: any CKDigest
            switch hashFunction {
                case .sha1:
                    digest = Insecure.SHA1.hash(data: data)
                case .sha256:
                    digest = SHA256.hash(data: data)
                case .sha384:
                    digest = SHA384.hash(data: data)
                case .sha512:
                    digest = SHA512.hash(data: data)
            }
            
            // Verify the signature
            switch padding {
                case .pkcs1v1_5:
                    return rsaPublicKey.isValidSignature(
                        _RSA.Signing.RSASignature(rawRepresentation: signature),
                        for: digest,
                        padding: .insecurePKCS1v1_5
                    )
                case .pss:
                    return rsaPublicKey.isValidSignature(
                        _RSA.Signing.RSASignature(rawRepresentation: signature),
                        for: digest,
                        padding: .PSS
                    )
                default:
                    throw CoseError.valueError("Unsupported padding")
            }
            
        } catch {
            return false
        }
    }
}

/// RSA with PSS padding
public class RsaPss: RsaAlgorithm {
    override public var padding: Padding {
        return .pss
    }
}

/// Base class for RSA with OAEP padding
public class RsaOaep: RsaAlgorithm {
    override public var padding: Padding {
        return .oaep
    }

    func keyWrap(key: RSAKey, data: Data) throws -> Data {
        let parts = try publicParts(of: key)
        let rsaPublicKey: _RSA.Encryption.PublicKey
        do {
            rsaPublicKey = try _RSA.Encryption.PublicKey(n: parts.n, e: parts.e)
        } catch {
            throw CoseError.invalidKey("Invalid RSA key: \(error)")
        }
        
        switch padding {
            case .oaep:
                return try rsaPublicKey
                    .encrypt(
                        data,
                        padding: _RSA.Encryption.Padding.PKCS1_OAEP
                    )
            default:
                throw CoseError.valueError("Unsupported padding")
        }
    }

    func keyUnwrap(key: RSAKey, data: Data) throws -> Data {
        // Construct the private key
        let parts = try privateParts(of: key)
        let privateKey: _RSA.Encryption.PrivateKey
        do{
            privateKey =  try _RSA.Encryption.PrivateKey(
                n: parts.n, e: parts.e, d: parts.d, p: parts.p, q: parts.q
            )
        } catch {
            throw CoseError.valueError("Invalid RSA key: \(error.localizedDescription)")
        }
        
        switch padding {
            case .oaep:
                return try privateKey.decrypt(
                    data,
                    padding: _RSA.Encryption.Padding.PKCS1_OAEP
                )
            default:
                throw CoseError.valueError("Unsupported padding")
        }
        
        
    }
}

/// RSA with PKCS#1 padding
public class RsaPkcs1: RsaAlgorithm {
    override public var padding: Padding {
        return .pkcs1v1_5
    }
}

/// PS256
public class Ps256: RsaPss {
    public init() {
        super.init(
            identifier: .ps256,
            fullname: "PS256",
            hashFunction: .sha256
        )
    }
}

/// PS384
public class Ps384: RsaPss {
    public init() {
        super.init(
            identifier: .ps384,
            fullname: "PS384",
            hashFunction: .sha384
        )
    }
}

/// PS512
public class Ps512: RsaPss {
    public init() {
        super.init(
            identifier: .ps512,
            fullname: "PS512",
            hashFunction: .sha512
        )
    }
}

/// RSAES-OAEP-SHA1
public class RsaesOaepSha1: RsaOaep {
    public init() {
        super.init(
            identifier: .rsa_ES_OAEP_SHA1,
            fullname: "RSAES_OAEP_SHA_1",
            hashFunction: .sha1
        )
    }
}

/// RSAES-OAEP-SHA256
public class RsaesOaepSha256: RsaOaep {
    public init() {
        super.init(
            identifier: .rsa_ES_OAEP_SHA256,
            fullname: "RSAES_OAEP_SHA_256",
            hashFunction: .sha256
        )
    }
}

/// RSAES-OAEP-SHA512
public class RsaesOaepSha512: RsaOaep {
    public init() {
        super.init(
            identifier: .rsa_ES_OAEP_SHA512,
            fullname: "RSAES_OAEP_SHA_512",
            hashFunction: .sha512
        )
    }
}

/// RSASSA-PKCS1-v1_5 using SHA-1
public class RsaPkcs1Sha1: RsaPkcs1 {
    public init() {
        super.init(
            identifier: .rsa_PKCS1_SHA1,
            fullname: "RS1",
            hashFunction: .sha1
        )
    }
}

/// RSASSA-PKCS1-v1_5 using SHA-256
public class RsaPkcs1Sha256: RsaPkcs1 {
    public init() {
        super.init(
            identifier: .rsa_PKCS1_SHA256,
            fullname: "RS256",
            hashFunction: .sha256
        )
    }
}

/// RSASSA-PKCS1-v1_5 using SHA-384
public class RsaPkcs1Sha384: RsaPkcs1 {
    public init() {
        super.init(
            identifier: .rsa_PKCS1_SHA384,
            fullname: "RS384",
            hashFunction: .sha384
        )
    }
}

/// RSASSA-PKCS1-v1_5 using SHA-512
public class RsaPkcs1Sha512: RsaPkcs1 {
    public init() {
        super.init(
            identifier: .rsa_PKCS1_SHA512,
            fullname: "RS512",
            hashFunction: .sha512
        )
    }
}
