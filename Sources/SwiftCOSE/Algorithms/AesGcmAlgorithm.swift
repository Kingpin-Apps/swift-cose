import Foundation
import CryptoSwift

public class AesGcmAlgorithm: EncAlgorithm  {
    public func encrypt(key: CoseSymmetricKey, nonce: Data, data: Data, aad: Data?) throws -> Data {
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
