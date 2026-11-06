import Foundation
import CryptoSwift


public class AesMacAlgorithm: CoseAlgorithm {
    public var digestLength: Int
    public var keyLength: Int
    
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        digestLength: Int,
        keyLength: Int
    ) {
        self.digestLength = digestLength
        self.keyLength = keyLength
        super.init(identifier: identifier, fullname: fullname)
    }

    public func computeTag(key: CoseSymmetricKey, data: Data) throws -> Data {
        let blockSize = 16
        var paddedData = data

        // Pad the data to a multiple of the block size
        while paddedData.count % blockSize != 0 {
            paddedData.append(0)
        }
        
        let cbc = CBC(iv: Data(repeating: 0, count: blockSize).toBytes)

        let aes = try AES(
            key: key.k.toBytes,
            blockMode: cbc
        )
        var encryptor = try aes.makeEncryptor()
        
        do {
            var ciphertext = Array<UInt8>()
            ciphertext += try encryptor.update(withBytes: data.toBytes)
            ciphertext += try encryptor.finish()

            if digestLength == 16 {
                return Data(ciphertext.suffix(16))
            } else {
                return Data(ciphertext.dropLast(8).suffix(8))
            }
        } catch {
            throw CoseError.genericError("Compute Tag failed: \(error.localizedDescription)")
        }
    }

    public func verifyTag(key: CoseSymmetricKey, tag: Data, data: Data) throws -> Bool {
        do {
            let computedTag = try computeTag(key: key, data: data)
            return computedTag == tag
        } catch {
            throw CoseError.genericError("Verify Tag failed: \(error.localizedDescription)")
        }
    }
}


// AES_MAC_128_64
public class AESMAC12864: AesMacAlgorithm {
    public init() {
        super.init(
            identifier: .aesMAC_128_64,
            fullname: "AES_MAC_128_64",
            digestLength: 8,
            keyLength: 16
        )
    }
}

// AES_MAC_256_64
public class AESMAC25664: AesMacAlgorithm {
    public init() {
        super.init(
            identifier: .aesMAC_256_64,
            fullname: "AES_MAC_256_64",
            digestLength: 8,
            keyLength: 32
        )
    }
}

// AES_MAC_128_128
public class AESMAC128128: AesMacAlgorithm {
    public init() {
        super.init(
            identifier: .aesMAC_128_128,
            fullname: "AES_MAC_128_128",
            digestLength: 16,
            keyLength: 16
        )
    }
}

// AES_MAC_256_128
public class AESMAC256128: AesMacAlgorithm {
    public init() {
        super.init(
            identifier: .aesMAC_256_128,
            fullname: "AES_MAC_256_128",
            digestLength: 16,
            keyLength: 32
        )
    }
}
