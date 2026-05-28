import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Crypto)
import Crypto
#endif
#if canImport(OpenSSL)
import OpenSSL
#endif
#if canImport(CCOSEOpenSSL)
import CCOSEOpenSSL
#endif
#if canImport(Goldilocks)
import Goldilocks
#endif

public class HashAlgorithm: CoseAlgorithm {
    public var hashAlgorithm: CoseAlgorithmIdentifier
    public var truncSize: Int?

    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        truncSize: Int? = nil
    ) {
        self.hashAlgorithm = identifier
        self.truncSize = truncSize
        super.init(identifier: identifier, fullname: fullname)
    }

    public func computeHash(data: Data) throws -> Data {
        let hash: [UInt8]
        switch hashAlgorithm {
            case .sha1:
                hash = Array(Insecure.SHA1.hash(data: data))
            case .sha256, .sha256_64:
                hash = Array(SHA256.hash(data: data))
            case .sha384:
                hash = Array(SHA384.hash(data: data))
            case .sha512, .sha512_256:
                hash = Array(SHA512.hash(data: data))
            case .shake128:
                hash = try Self.evpShake(data: data, outputBytes: 32, variant: .shake128)
            case .shake256:
                hash = try Self.evpShake(data: data, outputBytes: 64, variant: .shake256)
            default:
                throw CoseError.invalidAlgorithm("Unsupported hash algorithm")
        }

        var digest = Data(hash)

        if let truncSize = truncSize {
            digest = digest.prefix(truncSize)
        }

        return digest
    }

    private enum ShakeVariant {
        case shake128
        case shake256
    }

    private static func evpShake(data: Data, outputBytes: Int, variant: ShakeVariant) throws -> [UInt8] {
        #if canImport(OpenSSL) || canImport(CCOSEOpenSSL)
        guard let ctx = EVP_MD_CTX_new() else {
            throw CoseError.invalidAlgorithm("EVP_MD_CTX_new failed")
        }
        defer { EVP_MD_CTX_free(ctx) }

        let md = (variant == .shake128) ? EVP_shake128() : EVP_shake256()
        guard EVP_DigestInit_ex(ctx, md, nil) == 1 else {
            throw CoseError.invalidAlgorithm("EVP_DigestInit_ex failed for SHAKE")
        }

        let updateOK: Int32 = data.withUnsafeBytes { buf in
            guard let base = buf.baseAddress, buf.count > 0 else {
                return EVP_DigestUpdate(ctx, nil, 0)
            }
            return EVP_DigestUpdate(ctx, base, buf.count)
        }
        guard updateOK == 1 else {
            throw CoseError.invalidAlgorithm("EVP_DigestUpdate failed for SHAKE")
        }

        var output = [UInt8](repeating: 0, count: outputBytes)
        let finalOK: Int32 = output.withUnsafeMutableBufferPointer { buf in
            EVP_DigestFinalXOF(ctx, buf.baseAddress, outputBytes)
        }
        guard finalOK == 1 else {
            throw CoseError.invalidAlgorithm("EVP_DigestFinalXOF failed for SHAKE")
        }
        return output
        #elseif canImport(Goldilocks)
        // libgoldilocks SHAKE — used on platforms without OpenSSL EVP
        // (currently Android and Wasm). Self-contained Keccak impl shared
        // with swift-curve448 via the swift-goldilocks package.
        switch variant {
        case .shake128:
            return Goldilocks.SHAKE128.hash(data, outputByteCount: outputBytes)
        case .shake256:
            return Goldilocks.SHAKE256.hash(data, outputByteCount: outputBytes)
        }
        #else
        throw CoseError.invalidAlgorithm("SHAKE is unavailable on this platform (no OpenSSL EVP, no Goldilocks)")
        #endif
    }
}

public class Sha1: HashAlgorithm {
    public init() {
        super.init(identifier: .sha1, fullname: "SHA-1")
    }
}

public class Sha256: HashAlgorithm {
    public init() {
        super.init(identifier: .sha256, fullname: "SHA-256")
    }
}

public class Sha256Trunc64: HashAlgorithm {
    public init() {
        super.init(identifier: .sha256_64, fullname: "SHA-256/64", truncSize: 8)
    }
}

public class Sha384: HashAlgorithm {
    public init() {
        super.init(identifier: .sha384, fullname: "SHA-384")
    }
}

public class Sha512: HashAlgorithm {
    public init() {
        super.init(identifier: .sha512, fullname: "SHA-512")
    }
}

public class Sha512Trunc64: HashAlgorithm {
    public init() {
        super.init(identifier: .sha512_256, fullname: "SHA-512/256", truncSize: 32)
    }
}

public class Shake128: HashAlgorithm {
    public init() {
        super.init(identifier: .shake128, fullname: "SHAKE-128")
    }
}


public class Shake256: HashAlgorithm {
    public init() {
        super.init(identifier: .shake256, fullname: "SHAKE-256")
    }
}
