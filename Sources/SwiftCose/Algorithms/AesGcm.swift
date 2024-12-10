import Foundation
import CryptoSwift

public class AesGcmlgorithm: EncAlgorithm  {
    public func encrypt(key: CoseSymmetricKey, nonce: Data, data: Data, aad: Data?) throws -> Data {
        let aes = try! AES(
            key: key.k.toBytes,
            blockMode:
                GCM(
                    iv: nonce.toBytes,
                    additionalAuthenticatedData: aad?.toBytes
                ),
            padding: .noPadding
        )
        let encrypted = try! aes.encrypt(data.toBytes)
        return encrypted.toData
    }

    public func decrypt(key: CoseSymmetricKey, nonce: Data, ciphertext: Data, aad: Data?) throws -> Data {
        let aes = try! AES(
            key: key.k.toBytes,
            blockMode:
                GCM(
                    iv: nonce.toBytes,
                    additionalAuthenticatedData: aad?.toBytes
                ),
            padding: .noPadding
        )
        let decrypted = try! aes.decrypt(ciphertext.toBytes)
        return decrypted.toData
    }
}

/// AES-GCM mode with a 128-bit key and 128-bit tag
public class A128GCM: AesGcmlgorithm {
    public init() {
        super.init(identifier: .aesGCM_128, fullname: "A128GCM", keyLength: 16)
    }
}

/// AES-GCM mode with a 192-bit key and 128-bit tag
public class A192GCM: AesGcmlgorithm {
    public init() {
        super.init(identifier: .aesGCM_192, fullname: "A192GCM", keyLength: 24)
    }
}

/// AES-GCM mode with a 256-bit key and 128-bit tag
public class A256GCM: AesGcmlgorithm {
    public init() {
        super.init(identifier: .aesGCM_256, fullname: "A256GCM", keyLength: 32)
    }
}