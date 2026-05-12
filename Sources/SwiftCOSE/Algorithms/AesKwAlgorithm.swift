import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public class AesKwAlgorithm: EncAlgorithm {
    public func keyWrap(kek: CoseSymmetricKey, data: Data) throws -> Data {
        guard keyLength == kek.k.count else {
            throw CoseError.invalidKey("Key has the wrong length")
        }
        
        guard data.count >= 16 else {
            throw CoseError.valueError("The key to wrap must be at least 16 bytes")
        }
        
        guard data.count % 8 == 0 else {
            throw CoseError.valueError("The key to wrap must be a multiple of 8 bytes")
        }
        
        // Use the AES Key Wrap algorithm (RFC 3394) for key wrapping
        do {
            let wrappedKey = try AES.KeyWrap.wrap(
                SymmetricKey(data: data),
                using: SymmetricKey(data: kek.k)
            )
            return wrappedKey
        } catch {
            throw CoseError.genericError("Key Wrap failed: \(error.localizedDescription)")
        }
    }

    public func keyUnwrap(kek: CoseSymmetricKey, data: Data) throws -> Data {
        guard keyLength == kek.k.count else {
            throw CoseError.valueError("Key has the wrong length")
        }
        
        guard data.count >= 24 else {
            throw CoseError.valueError("Must be at least 24 bytes")
        }
        
        guard data.count % 8 == 0 else {
            throw CoseError.valueError("The wrapped key must be a multiple of 8 bytes")
        }
        
        // Use the AES Key Unwrap algorithm (RFC 3394) for key unwrapping
        do {
            let unwrappedKey = try AES.KeyWrap.unwrap(
                data.toBytes,
                using: SymmetricKey(data: kek.k)
            )
            return unwrappedKey.withUnsafeBytes { Data($0) }
        } catch {
            throw CoseError.genericError("Key Unwrap failed: \(error.localizedDescription)")
        }
    }
}

/// AES Key Wrap with a 128-bit key
public class A128KW: AesKwAlgorithm {
    public init() {
        super.init(identifier: .aesKW_128, fullname: "A128KW", keyLength: 16)
    }
}

/// AES Key Wrap with a 192-bit key
public class A192KW: AesKwAlgorithm {
    public init() {
        super.init(identifier: .aesKW_192, fullname: "A192KW", keyLength: 24)
    }
}

// AES Key Wrap with a 256-bit key
public class A256KW: AesKwAlgorithm {
    public init() {
        super.init(identifier: .aesKW_256, fullname: "A256KW", keyLength: 32)
    }
}

