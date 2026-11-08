import Foundation
import CryptoSwift


public class AesCcmAlgorithm: EncAlgorithm {
    public var tagLength: Int
    
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        keyLength: Int,
        tagLength: Int
    ) {
        self.tagLength = tagLength
        super.init(identifier: identifier, fullname: fullname, keyLength: keyLength)
    }

    /// RFC 9053 section 4.2: the AES-CCM-16-* algorithms use L = 2 and a
    /// 13-byte nonce; the AES-CCM-64-* algorithms use L = 8 and a 7-byte nonce.
    public var nonceLength: Int {
        switch CoseAlgorithmIdentifier(rawValue: identifier ?? 0) {
        case .aesCCM_16_64_128, .aesCCM_16_64_256, .aesCCM_16_128_128, .aesCCM_16_128_256: return 13
        default: return 7
        }
    }

    /// Checks key length, nonce length and message length before CryptoSwift
    /// sees them. Its CCM code traps on a nonce of 15 bytes or more, and it
    /// silently truncates a length or counter that does not fit in L bytes,
    /// which repeats keystream.
    func checkParameters(key: CoseSymmetricKey, nonce: Data, messageLength: Int) throws {
        if let keyLength, key.k.count != keyLength {
            throw CoseError.invalidKey("\(fullname) needs a \(keyLength)-byte key, not \(key.k.count)")
        }
        guard nonce.count == nonceLength else {
            throw CoseError.invalidIV("\(fullname) needs a \(nonceLength)-byte IV, not \(nonce.count)")
        }
        let l = 15 - nonceLength
        if l < 8, messageLength >= 1 << (8 * l) {
            throw CoseError.valueError("Message too long for \(fullname): at most \((1 << (8 * l)) - 1) bytes")
        }
    }

    public func encrypt(key: CoseSymmetricKey, nonce: Data, data: Data, aad: Data?) throws -> Data {
        try checkParameters(key: key, nonce: nonce, messageLength: data.count)
        let ccm = CCM(
            iv: nonce.toBytes,
            tagLength: tagLength,
            messageLength: data.count,
            additionalAuthenticatedData: aad?.toBytes
        )
        
        let aes = try AES(
            key: key.k.toBytes,
            blockMode: ccm,
            padding: .noPadding
        )
        
        do {
            let encrypted = try aes.encrypt(data.toBytes)
            return encrypted.toData
        } catch {
            throw CoseError.genericError("Encryption failed: \(error.localizedDescription)")
        }
    }

    public func decrypt(key: CoseSymmetricKey, nonce: Data, ciphertext: Data, aad: Data?) throws -> Data {
        guard ciphertext.count >= tagLength else {
            throw CoseError.valueError("Ciphertext is shorter than the AES-CCM tag")
        }
        try checkParameters(key: key, nonce: nonce, messageLength: ciphertext.count - tagLength)
        let ccm = CCM(
            iv: nonce.toBytes,
            tagLength: tagLength,
            messageLength: ciphertext.count - tagLength,
            additionalAuthenticatedData: aad?.toBytes
        )
        
        let aes = try AES(
            key: key.k.toBytes,
            blockMode: ccm,
            padding: .noPadding
        )
        
        do {
            let decrypted = try aes.decrypt(ciphertext.toBytes)
            return decrypted.toData
        } catch {
            throw CoseError.genericError("Decryption failed: \(error.localizedDescription)")
        }
    }
}

/// AES-CCM with a tag length of 8 bytes and a key length of 16 bytes
public class AESCCM1664128: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_16_64_128,
            fullname: "AES_CCM_16_64_128",
            keyLength: 16,
            tagLength: 8
        )
    }
}

/// AES-CCM with a tag length of 8 bytes and a key length of 32 bytes
public class AESCCM1664256: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_16_64_256,
            fullname: "AES_CCM_16_64_256",
            keyLength: 32,
            tagLength: 8
        )
    }
}

/// AES-CCM with a tag length of 8 bytes and a key length of 16 bytes
public class AESCCM6464128: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_64_64_128,
            fullname: "AES_CCM_64_64_128",
            keyLength: 16,
            tagLength: 8
        )
    }
}

/// AES-CCM with a tag length of 8 bytes and a key length of 32 bytes
public class AESCCM6464256: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_64_64_256,
            fullname: "AES_CCM_64_64_256",
            keyLength: 32,
            tagLength: 8
        )
    }
}

/// AES-CCM with a tag length of 16 bytes and a key length of 16 bytes
public class AESCCM16128128: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_16_128_128,
            fullname: "AES_CCM_16_128_128",
            keyLength: 16,
            tagLength: 16
        )
    }
}

/// AES-CCM with a tag length of 16 bytes and a key length of 32 bytes
public class AESCCM16128256: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_16_128_256,
            fullname: "AES_CCM_16_128_256",
            keyLength: 32,
            tagLength: 16
        )
    }
}

/// AES-CCM with a tag length of 16 bytes and a key length of 16 bytes
public class AESCCM64128128: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_64_128_128,
            fullname: "AES_CCM_64_128_128",
            keyLength: 16,
            tagLength: 16
        )
    }
}

/// AES-CCM with a tag length of 16 bytes and a key length of 32 bytes
public class AESCCM64128256: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_64_128_256,
            fullname: "AES_CCM_64_128_256",
            keyLength: 32,
            tagLength: 16
        )
    }
}
