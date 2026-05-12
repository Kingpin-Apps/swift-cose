import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public enum CoseHashFunction {
    case sha1
    case sha256
    case sha384
    case sha512
}

public class HmacAlgorithm: CoseAlgorithm {
    public var hashFunction: CoseHashFunction
    public var digestLength: Int
    
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        digestLength: Int,
        hashFunction: CoseHashFunction
    ) {
        self.hashFunction = hashFunction
        self.digestLength = digestLength
        super.init(identifier: identifier, fullname: fullname)
    }
    
    public func computeTag(key: CoseSymmetricKey, data: Data) throws -> Data {
        var out: Data
        let symKey = SymmetricKey(data: key.k)
        switch hashFunction {
            case .sha256:
                var hmac = HMAC<SHA256>.init(key: symKey)
                hmac.update(data: data)
                let digest = hmac.finalize()
                out = digest.withUnsafeBytes { Data($0) }
            case .sha384:
                var hmac = HMAC<SHA384>.init(key: symKey)
                hmac.update(data: data)
                let digest = hmac.finalize()
                out = digest.withUnsafeBytes { Data($0) }
            case .sha512:
                var hmac = HMAC<SHA512>.init(key: symKey)
                hmac.update(data: data)
                let digest = hmac.finalize()
                out = digest.withUnsafeBytes { Data($0) }
            default:
                throw CoseError.invalidAlgorithm("Unsupported hash function")
        }
        return out.prefix(digestLength)
    }
    
    public func verifyTag(key: CoseSymmetricKey, tag: Data, data: Data) throws -> Bool {
        let computedTag = try computeTag(key: key, data: data)
        return tag == computedTag
    }
}

public class Hmac256: HmacAlgorithm {
    public init() {
        super.init(
            identifier: .hmacSHA256,
            fullname: "HMAC_256",
            digestLength: 32,
            hashFunction: .sha256
        )
    }
}

public class Hmac25664: HmacAlgorithm {
    public init() {
        super.init(
            identifier: .hmacSHA256_64,
            fullname: "HMAC_256_64",
            digestLength: 8,
            hashFunction: .sha256
        )
    }
}

public class Hmac384: HmacAlgorithm {
    public init() {
        super.init(
            identifier: .hmacSHA384,
            fullname: "HMAC_384",
            digestLength: 48,
            hashFunction: .sha384
        )
    }
}

public class Hmac512: HmacAlgorithm {
    public init() {
        super.init(
            identifier: .hmacSHA512,
            fullname: "HMAC_512",
            digestLength: 64,
            hashFunction: .sha512
        )
    }
}
