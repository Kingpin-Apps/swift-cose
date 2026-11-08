import Foundation
import CryptoSwift

public class AesGcmAlgorithm: EncAlgorithm  {
    /// RFC 9053 section 4.1: AES-GCM in COSE uses a 96-bit IV and a 128-bit tag.
    static let nonceLength = 12
    static let tagLength = 16

    /// Checks the key and IV lengths against the algorithm before CryptoSwift
    /// sees them.
    func checkParameters(key: CoseSymmetricKey, nonce: Data) throws {
        if let keyLength, key.k.count != keyLength {
            throw CoseError.invalidKey("\(fullname) needs a \(keyLength)-byte key, not \(key.k.count)")
        }
        guard nonce.count == Self.nonceLength else {
            throw CoseError.invalidIV("\(fullname) needs a \(Self.nonceLength)-byte IV, not \(nonce.count)")
        }
    }

    public func encrypt(key: CoseSymmetricKey, nonce: Data, data: Data, aad: Data?) throws -> Data {
        try checkParameters(key: key, nonce: nonce)
        let gcm = GCM(
            iv: nonce.toBytes,
            additionalAuthenticatedData: aad?.toBytes,
            mode: .combined
        )
        // GCM is a stream mode: no padding, or the ciphertext grows to a
        // block multiple and no other COSE implementation can read it.
        let aes = try AES(
            key: key.k.toBytes,
            blockMode: gcm,
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
        try checkParameters(key: key, nonce: nonce)
        // A ciphertext shorter than the tag would make CryptoSwift take a
        // negative-length prefix, which traps.
        guard ciphertext.count >= Self.tagLength else {
            throw CoseError.valueError("Ciphertext is shorter than the AES-GCM tag")
        }
        let gcm = GCM(
            iv: nonce.toBytes,
            additionalAuthenticatedData: aad?.toBytes,
            mode: .combined
        )
        // GCM is a stream mode: no padding, or the ciphertext grows to a
        // block multiple and no other COSE implementation can read it.
        let aes = try AES(
            key: key.k.toBytes,
            blockMode: gcm,
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

/// AES-GCM mode with a 128-bit key and 128-bit tag
public class A128GCM: AesGcmAlgorithm {
    public init() {
        super.init(identifier: .aesGCM_128, fullname: "A128GCM", keyLength: 16)
    }
}

/// AES-GCM mode with a 192-bit key and 128-bit tag
public class A192GCM: AesGcmAlgorithm {
    public init() {
        super.init(identifier: .aesGCM_192, fullname: "A192GCM", keyLength: 24)
    }
}

/// AES-GCM mode with a 256-bit key and 128-bit tag
public class A256GCM: AesGcmAlgorithm {
    public init() {
        super.init(identifier: .aesGCM_256, fullname: "A256GCM", keyLength: 32)
    }
}
