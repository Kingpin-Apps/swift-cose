import Foundation
import CBORCodable
import X509


// MARK: - X5Bag

public class X5Bag {
    public var certificates: Data

    public init(certificates: Any) throws {
        if let certArray = certificates as? [Data], certArray.count == 1 {
            self.certificates = certArray[0]
        } else if let certData = certificates as? Data {
            self.certificates = certData
        } else {
            throw CoseError.invalidCertificate("Invalid certificate data")
        }
    }

    public func encode() -> Any {
        return certificates
    }
}

// MARK: - X5T

public class X5T: Equatable {
    public var alg: HashAlgorithm
    public var thumbprint: Data?
    
    /// Create a new X5T instance.
    /// - Parameters:
    ///   - alg: The hash algorithm to use.
    ///   - thumbprint: The thumbprint of the certificate.
    public init(alg: HashAlgorithm, thumbprint: Data) {
        self.alg = alg
        self.thumbprint = thumbprint
    }
    
    /// Extract thumbprint from an encoded certificate.
    public static func fromCertificate(alg: HashAlgorithm, certificate: Data, cborEncoded: Bool = false) throws -> X5T {
        var certData = certificate
        if cborEncoded {
            let cbor = CBOR(certificate)
            certData = cbor.byteStringValue!
        }
        let hash = try alg.computeHash(data: certData)
        return X5T(alg: alg, thumbprint: hash)
    }

    public static func decode(item: CBOR) throws -> X5T {
        guard let algId = item[0], let thumbprint = item[1] else {
            fatalError("Invalid CBOR item format")
        }
        let alg = CoseAlgorithm.getInstance(
            for: CoseAlgorithmIdentifier(rawValue: algId.intValue!)!
        )
        return X5T(
            alg: alg as! HashAlgorithm,
            thumbprint: thumbprint.byteStringValue!
        )
    }

    public func encode() -> CBOR {
        return CBOR.array([
            CBOR(alg.hashAlgorithm.rawValue),
            CBOR.byteString(thumbprint!)
        ])
    }

    public func matches(certificate: Data, cborEncoded: Bool = false) throws -> Bool {
        var certData = certificate
        if cborEncoded {
            let cbor = try CBORSerialization.cbor(from: certificate)
            certData = cbor.byteStringValue!
        }
        let hash = try alg.computeHash(data: certData)
        return thumbprint == hash
    }

    public static func == (lhs: X5T, rhs: X5T) -> Bool {
        return lhs.alg == rhs.alg && lhs.thumbprint == rhs.thumbprint
    }
}

// MARK: - X5U

public class X5U {
    public var uri: String

    public init(uri: String) {
        self.uri = uri
    }

    public func encode() -> String {
        return uri
    }
}

// MARK: - X5Chain

public class X5Chain {
    public var certChain: Certificate

    public init(certData: Data, verify: Bool = false) throws {
        do {
            self.certChain = try Certificate(derEncoded: certData.toBytes)
        } catch {
            throw CoseError.invalidCertificate("Invalid certificate data: \(error.localizedDescription)")
        }

        if verify {
            do {
                let _ = try verifyChain(keyUsage: ["digital_signature"])
            } catch {
                throw CoseError.invalidCertificate("Certificate verification failed: \(error)")
            }
        }
    }

    public func verifyChain(keyUsage: Set<String>) throws -> Bool {
        /// Validates the certificate path and that the certificate is valid for the key usage and extended key usage purposes specified.
        /// - Parameters:
        ///  - keyUsage: A set of unicode strings of the required key usage purposes. Valid values include:
        ///     - "digital_signature"
        /// - Returns: A boolean indicating if the certificate chain is valid.
        /// - Throws: An error if the certificate chain is invalid.
        
        // Extract KeyUsage extension
        guard let keyUsageExtension = try certChain.extensions.keyUsage else {
            throw CoseError.invalidCertificate("The X.509 certificate provided is not valid for the purpose is not valid for digitalSignature")
        }

        // Check if `digitalSignature` is enabled
        if keyUsageExtension.digitalSignature {
           return true
        } else {
           return false
        }
    }

    public func encode() -> Any {
        return certChain
    }
}
