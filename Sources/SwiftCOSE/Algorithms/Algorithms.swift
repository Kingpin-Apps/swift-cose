import Foundation

public enum CoseAlgorithmIdentifier: Int, CaseIterable, Sendable {
    case aesCCM_16_64_128 = 10
    case aesCCM_16_64_256 = 11
    case aesCCM_64_64_128 = 12
    case aesCCM_64_64_256 = 13
    case aesCCM_16_128_128 = 30
    case aesCCM_16_128_256 = 31
    case aesCCM_64_128_128 = 32
    case aesCCM_64_128_256 = 33
    case aesGCM_128 = 1
    case aesGCM_192 = 2
    case aesGCM_256 = 3
    case aesKW_128 = -3
    case aesKW_192 = -4
    case aesKW_256 = -5
    case aesMAC_128_64 = 14
    case aesMAC_256_64 = 15
    case aesMAC_128_128 = 25
    case aesMAC_256_128 = 26
    case direct = -6
    case directHKDFAES128 = -12
    case directHKDFAES256 = -13
    case directHKDFSHA256 = -10
    case direcHKDFSHA512 = -11
    case edDSA = -8
    case es256 = -7
    case es384 = -35
    case es512 = -36
    case ecdhES_A128KW = -29
    case ecdhES_A192KW = -30
    case ecdhES_A256KW = -31
    case ecdhES_HKDF_256 = -25
    case ecdhES_HKDF_512 = -26
    case ecdhSS_A128KW = -32
    case ecdhSS_A192KW = -33
    case ecdhSS_A256KW = -34
    case ecdhSS_HKDF_256 = -27
    case ecdhSS_HKDF_512 = -28
    case hmacSHA256 = 5
    case hmacSHA256_64 = 4
    case hmacSHA384 = 6
    case hmacSHA512 = 7
    case ps256 = -37
    case ps384 = -38
    case ps512 = -39
    case rsa_ES_OAEP_SHA1 = -40
    case rsa_ES_OAEP_SHA256 = -41
    case rsa_ES_OAEP_SHA512 = -42
    case rsa_PKCS1_SHA1 = -65535
    case rsa_PKCS1_SHA256 = -257
    case rsa_PKCS1_SHA384 = -258
    case rsa_PKCS1_SHA512 = -259
    case sha1 = -14
    case sha256 = -16
    case sha256_64 = -15
    case sha384 = -43
    case sha512 = -44
    case sha512_256 = -17
    case shake128 = -18
    case shake256 = -45
    
    public static func fromCoseAlgorithm(_ alg: CoseAlgorithm) throws -> CoseAlgorithmIdentifier {
        if let fullname = alg.fullname {
            return CoseAlgorithmIdentifier.fromFullName(fullname)!
        } else if let identifier = alg.identifier {
            return CoseAlgorithmIdentifier(rawValue: identifier)!
        } else {
            throw CoseError.invalidAlgorithm("Algorithm not found in protected headers")
        }
    }
    
    /// Returns the appropriate `CoseAlgorithmIdentifier` for the given full name.
    /// - Parameter fullName: The string fullname of the algorithm.
    /// - Returns: The corresponding `CoseAlgorithmIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullName: String) -> CoseAlgorithmIdentifier? {
        switch fullName {
            case "AES_CCM_16_64_128": return .aesCCM_16_64_128
            case "AES_CCM_16_64_256": return .aesCCM_16_64_256
            case "AES_CCM_64_64_128": return .aesCCM_64_64_128
            case "AES_CCM_64_64_256": return .aesCCM_64_64_256
            case "AES_CCM_16_128_128": return .aesCCM_16_128_128
            case "AES_CCM_16_128_256": return .aesCCM_16_128_256
            case "AES_CCM_64_128_128": return .aesCCM_64_128_128
            case "AES_CCM_64_128_256": return .aesCCM_64_128_256
            case "A128GCM": return .aesGCM_128
            case "A192GCM": return .aesGCM_192
            case "A256GCM": return .aesGCM_256
            case "A128KW": return .aesKW_128
            case "A192KW": return .aesKW_192
            case "A256KW": return .aesKW_256
            case "AES_MAC_128_64": return .aesMAC_128_64
            case "AES_MAC_256_64": return .aesMAC_256_64
            case "AES_MAC_128_128": return .aesMAC_128_128
            case "AES_MAC_256_128": return .aesMAC_256_128
            case "DIRECT": return .direct
            case "DIRECT_HKDF_AES_128": return .directHKDFAES128
            case "DIRECT_HKDF_AES_256": return .directHKDFAES256
            case "DIRECT_HKDF_SHA_256": return .directHKDFSHA256
            case "DIRECT_HKDF_SHA_512": return .direcHKDFSHA512
            case "EDDSA": return .edDSA
            case "ES256": return .es256
            case "ES384": return .es384
            case "ES512": return .es512
            case "ECDH_ES_A128KW": return .ecdhES_A128KW
            case "ECDH_ES_A192KW": return .ecdhES_A192KW
            case "ECDH_ES_A256KW": return .ecdhES_A256KW
            case "ECDH_ES_HKDF_256": return .ecdhES_HKDF_256
            case "ECDH_ES_HKDF_512": return .ecdhES_HKDF_512
            case "ECDH_SS_A128KW": return .ecdhSS_A128KW
            case "ECDH_SS_A192KW": return .ecdhSS_A192KW
            case "ECDH_SS_A256KW": return .ecdhSS_A256KW
            case "ECDH_SS_HKDF_256": return .ecdhSS_HKDF_256
            case "ECDH_SS_HKDF_512": return .ecdhSS_HKDF_512
            case "HMAC_256": return .hmacSHA256
            case "HMAC_256_64": return .hmacSHA256_64
            case "HMAC_384": return .hmacSHA384
            case "HMAC_512": return .hmacSHA512
            case "PS256": return .ps256
            case "PS384": return .ps384
            case "PS512": return .ps512
            case "RSAES_OAEP_SHA_1": return .rsa_ES_OAEP_SHA1
            case "RSAES_OAEP_SHA_256": return .rsa_ES_OAEP_SHA256
            case "RSAES_OAEP_SHA_512": return .rsa_ES_OAEP_SHA512
            case "RS1": return .rsa_PKCS1_SHA1
            case "RS256": return .rsa_PKCS1_SHA256
            case "RS384": return .rsa_PKCS1_SHA384
            case "RS512": return .rsa_PKCS1_SHA512
            case "SHA-1": return .sha1
            case "SHA-256": return .sha256
            case "SHA-256/64": return .sha256_64
            case "SHA-384": return .sha384
            case "SHA-512": return .sha512
            case "SHA-512/256": return .sha512_256
            case "SHAKE-128": return .shake128
            case "SHAKE-256": return .shake256
            default: return nil
        }
    }
}

/// Base class for all COSE algorithms.
public class CoseAlgorithm: CoseAttribute {
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        valueParser: ((Any) throws -> Any)? = nil
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname, valueParser: valueParser)
    }
    
    // MARK: - Codable Protocol
//    required public init(from decoder: Decoder) throws {
//        let container = try decoder.container(keyedBy: CodingKeys.self)
//        self.identifier = try container.decode(Int.self, forKey: .identifier)
//        self.fullname = try container.decode(String.self, forKey: .fullname)
//    }
    
//    public func encode(to encoder: Encoder) throws {
//        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(identifier, forKey: .identifier)
////        try container.encode(fullname, forKey: .fullname)
//    }

    public static func fromId(for attribute: Any) throws -> CoseAlgorithm {
        switch attribute {
            case let id as Int:
                // If the identifier is an Int, convert it to CoseAlgorithmIdentifier
                guard let alg = CoseAlgorithmIdentifier(rawValue: id) else {
                    throw CoseError.invalidAlgorithm("Unknown algorithm identifier")
                }
                return getInstance(for: alg)
                
            case let id as Int64:
                // Ensure UInt64 fits within Int bounds
                guard id <= Int64(Int.max) else {
                    throw CoseError.invalidKeyType("UInt64 value exceeds Int max limit")
                }
                guard let type = CoseAlgorithmIdentifier(rawValue: Int(id)) else {
                    throw CoseError.invalidKeyType("Unknown algorithm identifier")
                }
                return getInstance(for: type)
                
            case let id as UInt64:
                // Ensure UInt64 fits within Int bounds
                guard id <= Int64(Int.max) else {
                    throw CoseError.invalidKeyType("UInt64 value exceeds Int max limit")
                }
                guard let type = CoseAlgorithmIdentifier(rawValue: Int(id)) else {
                    throw CoseError.invalidKeyType("Unknown algorithm identifier")
                }
                return getInstance(for: type)
                
            case let name as String:
                // If the identifier is a String, attempt to match it to a CoseAlgorithmIdentifier
                guard let alg = CoseAlgorithmIdentifier.fromFullName(name) else {
                    throw CoseError.invalidAlgorithm("Unknown algorithm fullname")
                }
                return getInstance(for: alg)
                
            case let alg as CoseAlgorithmIdentifier:
                // If the identifier is already a CoseAlgorithmIdentifier, get the instance directly
                return getInstance(for: alg)
                
            case let type as CoseAttribute:
                if let id = type.identifier {
                    guard let alg = CoseAlgorithmIdentifier(rawValue: id) else {
                        throw CoseError.invalidAlgorithm("Unknown algorithm identifier")
                    }
                    return getInstance(for: alg)
                } else if let fullname = type.fullname {
                    guard let alg = CoseAlgorithmIdentifier.fromFullName(fullname) else {
                        throw CoseError.invalidAlgorithm("Unknown algorithm fullname")
                    }
                    return getInstance(for: alg)
                } else {
                    throw CoseError.invalidAlgorithm("Algorithm identifier or fullname not found")
                }
            default:
                throw CoseError.invalidAlgorithm("Unsupported identifier type. Must be Int, String, or CoseAlgorithmIdentifier. Type: \(type(of: attribute))")
        }
    }
    
    public static func getInstance(for identifier: CoseAlgorithmIdentifier) -> CoseAlgorithm {
        switch identifier {
            case .aesCCM_16_64_128: return AESCCM1664128()
            case .aesCCM_16_64_256: return AESCCM1664256()
            case .aesCCM_64_64_128: return AESCCM6464128()
            case .aesCCM_64_64_256: return AESCCM6464256()
            case .aesCCM_16_128_128: return AESCCM16128128()
            case .aesCCM_16_128_256: return AESCCM16128256()
            case .aesCCM_64_128_128: return AESCCM64128128()
            case .aesCCM_64_128_256: return AESCCM64128256()
            case .aesGCM_128: return A128GCM()
            case .aesGCM_192: return A192GCM()
            case .aesGCM_256: return A256GCM()
            case .aesKW_128: return A128KW()
            case .aesKW_192: return A192KW()
            case .aesKW_256: return A256KW()
            case .aesMAC_128_64: return AESMAC12864()
            case .aesMAC_256_64: return AESMAC25664()
            case .aesMAC_128_128: return AESMAC128128()
            case .aesMAC_256_128: return AESMAC256128()
            case .direct: return Direct()
            case .directHKDFAES128: return DirectHKDFAES128()
            case .directHKDFAES256: return DirectHKDFAES256()
            case .directHKDFSHA256: return DirectHKDFSHA256()
            case .direcHKDFSHA512: return DirecHKDFSHA512()
            case .edDSA: return EdDSAAlgorithm()
            case .es256: return Es256()
            case .es384: return Es384()
            case .es512: return Es512()
            case .ecdhES_A128KW: return EcdhEsA128KW()
            case .ecdhES_A192KW: return EcdhEsA192KW()
            case .ecdhES_A256KW: return EcdhEsA256KW()
            case .ecdhES_HKDF_256: return EcdhEsHKDF256()
            case .ecdhES_HKDF_512: return EcdhEsHKDF512()
            case .ecdhSS_A128KW: return EcdhSsA128KW()
            case .ecdhSS_A192KW: return EcdhSsA192KW()
            case .ecdhSS_A256KW: return EcdhSsA256KW()
            case .ecdhSS_HKDF_256: return EcdhSsHKDF256()
            case .ecdhSS_HKDF_512: return EcdhSsHKDF512()
            case .hmacSHA256: return Hmac256()
            case .hmacSHA256_64: return Hmac25664()
            case .hmacSHA384: return Hmac384()
            case .hmacSHA512: return Hmac512()
            case .ps256: return Ps256()
            case .ps384: return Ps384()
            case .ps512: return Ps512()
            case .rsa_ES_OAEP_SHA1: return RsaesOaepSha1()
            case .rsa_ES_OAEP_SHA256: return RsaesOaepSha256()
            case .rsa_ES_OAEP_SHA512: return RsaesOaepSha512()
            case .rsa_PKCS1_SHA1: return RsaPkcs1Sha1()
            case .rsa_PKCS1_SHA256: return RsaPkcs1Sha256()
            case .rsa_PKCS1_SHA384: return RsaPkcs1Sha384()
            case .rsa_PKCS1_SHA512: return RsaPkcs1Sha512()
            case .sha1: return Sha1()
            case .sha256: return Sha256()
            case .sha256_64: return Sha256Trunc64()
            case .sha384: return Sha384()
            case .sha512: return Sha512()
            case .sha512_256: return Sha512Trunc64()
            case .shake128: return Shake128()
            case .shake256: return Shake256()
        }
    }

}

public class EncAlgorithm: CoseAlgorithm {
    public var keyLength: Int?
    
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        keyLength: Int? = nil
    ) {
        self.keyLength = keyLength
        super.init(identifier: identifier, fullname: fullname)
    }
}

/// Direct use of CEK
public class Direct: CoseAlgorithm {
    public init() {
        super.init(identifier: .direct, fullname: "DIRECT")
    }
}

/// Shared secret w/ AES-MAC 128-bit key
public class DirectHKDFAES128: CoseAlgorithm {
    public init() {
        super.init(identifier: .directHKDFAES128, fullname: "DIRECT_HKDF_AES_128")
    }
}

/// Shared secret w/ AES-MAC 256-bit key
public class DirectHKDFAES256: CoseAlgorithm {
    public init() {
        super.init(identifier: .directHKDFAES256, fullname: "DIRECT_HKDF_AES_256")
    }
}

/// Shared secret w/ HKDF and SHA-256
public class DirectHKDFSHA256: CoseAlgorithm {
    public init() {
        super.init(identifier: .directHKDFSHA256, fullname: "DIRECT_HKDF_SHA_256")
    }
}

/// Shared secret w/ HKDF and SHA-512
public class DirecHKDFSHA512: CoseAlgorithm {
    public init() {
        super.init(identifier: .direcHKDFSHA512, fullname: "DIRECT_HKDF_SHA_512")
    }
}

