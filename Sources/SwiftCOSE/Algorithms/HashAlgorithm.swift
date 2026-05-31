import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Crypto)
import Crypto
#endif
import Goldilocks

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
                hash = Self.evpShake(data: data, outputBytes: 32, variant: .shake128)
            case .shake256:
                hash = Self.evpShake(data: data, outputBytes: 64, variant: .shake256)
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

    private static func evpShake(data: Data, outputBytes: Int, variant: ShakeVariant) -> [UInt8] {
        switch variant {
        case .shake128:
            return Goldilocks.SHAKE128.hash(data, outputByteCount: outputBytes)
        case .shake256:
            return Goldilocks.SHAKE256.hash(data, outputByteCount: outputBytes)
        }
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
