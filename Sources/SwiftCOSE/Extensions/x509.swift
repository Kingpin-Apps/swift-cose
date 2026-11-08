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

    /// Parses a certificate.
    ///
    /// With `verify: true` the certificate must be inside its validity
    /// period at `validationTime` and allow digital signatures, or this
    /// throws. That does not prove who issued it: use
    /// ``validate(trustRoots:intermediates:at:)`` for path validation.
    public init(certData: Data, verify: Bool = false, validationTime: Date = Date()) throws {
        do {
            self.certChain = try Certificate(derEncoded: certData.toBytes)
        } catch {
            throw CoseError.invalidCertificate("Invalid certificate data: \(error.localizedDescription)")
        }

        if verify {
            let valid: Bool
            do {
                valid = try verifyChain(keyUsage: ["digital_signature"], at: validationTime)
            } catch {
                throw CoseError.invalidCertificate("Certificate verification failed: \(error)")
            }
            guard valid else {
                throw CoseError.invalidCertificate("The certificate is expired, not yet valid, or not valid for the requested key usage.")
            }
        }
    }

    /// Checks that the certificate is inside its validity period at `date`
    /// and that its KeyUsage extension allows every purpose in `keyUsage`.
    ///
    /// This does not validate the certificate path or its issuer.
    ///
    /// - Parameters:
    ///   - keyUsage: The required key usage purposes: `digital_signature`,
    ///     `non_repudiation`, `key_encipherment`, `data_encipherment`,
    ///     `key_agreement`, `key_cert_sign`, `crl_sign`.
    ///   - date: The time to check the validity period against.
    /// - Returns: `true` when the certificate is valid at `date` for all the purposes.
    /// - Throws: When the certificate has no KeyUsage extension or a purpose is unknown.
    public func verifyChain(keyUsage: Set<String>, at date: Date = Date()) throws -> Bool {
        guard let usage = try certChain.extensions.keyUsage else {
            throw CoseError.invalidCertificate("The X.509 certificate has no KeyUsage extension.")
        }
        for purpose in keyUsage {
            let allowed: Bool
            switch purpose {
            case "digital_signature": allowed = usage.digitalSignature
            case "non_repudiation", "content_commitment": allowed = usage.nonRepudiation
            case "key_encipherment": allowed = usage.keyEncipherment
            case "data_encipherment": allowed = usage.dataEncipherment
            case "key_agreement": allowed = usage.keyAgreement
            case "key_cert_sign": allowed = usage.keyCertSign
            case "crl_sign": allowed = usage.cRLSign
            default: throw CoseError.invalidCertificate("Unknown key usage purpose \(purpose).")
            }
            if !allowed { return false }
        }
        return certChain.notValidBefore <= date && date <= certChain.notValidAfter
    }

    /// Validates the certificate path to one of `trustRoots` with the
    /// RFC 5280 policy, at `date`.
    ///
    /// - Returns: `true` when a valid chain to a trust root exists.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public func validate(trustRoots: [Certificate], intermediates: [Certificate] = [], at date: Date = Date()) async -> Bool {
        var verifier = Verifier(rootCertificates: CertificateStore(trustRoots)) {
            RFC5280Policy(validationTime: date)
        }
        let result = await verifier.validate(leaf: certChain, intermediates: CertificateStore(intermediates))
        if case .validCertificate = result { return true }
        return false
    }

    public func encode() -> Any {
        return certChain
    }
}
