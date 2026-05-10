import Testing
import CryptoKit
import Foundation
import X509
import SwiftASN1
import PotentCBOR
@testable import SwiftCOSE

struct X509Tests {
    
    // MARK: - X5Bag Tests
    
    @Test func testX5BagInitializationWithSingleCertificate() async throws {
        let certificate = Data([0x01, 0x02, 0x03])  // Simulated certificate data
        let bag = try X5Bag(certificates: certificate)
        
        #expect(bag.certificates == certificate)
    }
    
    @Test func testX5BagInitializationWithArray() async throws {
        let certificate = Data([0x01, 0x02, 0x03])
        let bag = try X5Bag(certificates: [certificate])
        
        #expect(bag.certificates == certificate)
    }
    
    @Test func testX5BagInitializationFails() async throws {
        #expect(throws: CoseError.self) {
            let _ = try X5Bag(certificates: "Invalid Format")
        }
    }
    
    // MARK: - X5T Tests
    
    @Test func testX5TInitialization() async throws {
        let thumbprint = Data([0x01, 0xAB, 0xCD])
        let algorithm = Sha256()
        
        let x5t = X5T(alg: algorithm, thumbprint: thumbprint)
        
        #expect(x5t.alg == algorithm)
        #expect(x5t.thumbprint == thumbprint)
    }
    
    @Test func testX5TThumbprintMatching() async throws {
        let certificate = Data([0x01, 0x02, 0x03])
        let algorithm = Sha256()
        let thumbprint = try algorithm.computeHash(data: certificate)
        
        let x5t = X5T(alg: algorithm, thumbprint: thumbprint)
        
        #expect(try x5t.matches(certificate: certificate) == true)
    }
    
    @Test func testX5TThumbprintMismatch() async throws {
        let certificate = Data([0x01, 0x02, 0x03])
        let otherCertificate = Data([0x04, 0x05, 0x06])
        let algorithm = Sha256()
        let thumbprint = try algorithm.computeHash(data: certificate)
        
        let x5t = X5T(alg: algorithm, thumbprint: thumbprint)
        
        #expect(try x5t.matches(certificate: otherCertificate) == false)
    }
    
    @Test func testX5TFromCertificate() async throws {
        // Load a valid DER-encoded certificate
        guard let filePath = Bundle.module.path(forResource: "valid_certificate", ofType: "der", inDirectory: "data/x509") else {
            fatalError("File not found: valid_certificate.der")
        }
        let certificate = try Data(contentsOf: URL(fileURLWithPath: filePath))
        
        // Define the hash algorithm to use
        let algorithm = Sha256()
        
        // Create X5T instance from certificate
        let x5t = try X5T.fromCertificate(alg: algorithm, certificate: certificate)
        
        // Compute expected thumbprint manually
        let expectedThumbprint = try algorithm.computeHash(data: certificate)
        
        // Assertions
        #expect(x5t.thumbprint == expectedThumbprint)
        #expect(x5t.alg == algorithm)
    }
    
    @Test func testX5TFromCBORCertificate() async throws {
        // Load a valid DER-encoded certificate
        let certCborHex = "014301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB01005840D4320B1D6849E309219D30037E138166F2508247DDDAE76CCEEA55053C108E90D551F6D60106F1ABB484CFBE6256C178E4AC3314EA19191E8B607DA5AE3BDA16"

        let certificateData = certCborHex.hexStringToData
        
        // Load a CBOR-encoded certificate (simulated)
        let certificateCBOR = CBOR(certificateData)
        let algorithm = Sha256()
        
        // Extract from CBOR encoded certificate
        let x5t = try X5T.fromCertificate(
            alg: algorithm,
            certificate: certificateData,
            cborEncoded: true
        )
        
        // Decode CBOR to extract raw DER
        let expectedThumbprint = try algorithm.computeHash(data: certificateCBOR.bytesStringValue!)
        
        // Assertions
        #expect(x5t.thumbprint == expectedThumbprint)
        #expect(x5t.alg == algorithm)
    }
    
    // MARK: - X5T Encode/Decode Tests
       
   @Test func testX5TEncode() async throws {
       // Simulate thumbprint data and algorithm
       let thumbprint = Data([0x01, 0x02, 0x03, 0x04])
       let algorithm = Sha256()
       
       // Create X5T instance
       let x5t = X5T(alg: algorithm, thumbprint: thumbprint)
       
       // Encode the X5T instance to CBOR
       let encodedCBOR = x5t.encode()
       
       // Assert correct CBOR structure
//       #expect(encodedCBOR.count == 2)
       #expect(encodedCBOR[0] == CBOR(integerLiteral: algorithm.hashAlgorithm.rawValue))
       #expect(encodedCBOR[1] == CBOR.byteString(thumbprint))
   }
   
   @Test func testX5TDecode() async throws {
       // Simulate CBOR encoded data
       let thumbprint = Data([0x01, 0x02, 0x03, 0x04])
       let algorithm = Sha256()
       let encodedCBOR: [CBOR] = [
        CBOR(integerLiteral: algorithm.hashAlgorithm.rawValue),
        CBOR.byteString(thumbprint)
       ]
       
       // Decode CBOR back to X5T instance
       let x5t = try X5T.decode(item: CBOR.array(encodedCBOR))
       
       // Validate decoded X5T instance
       #expect(x5t.alg == algorithm)
       #expect(x5t.thumbprint == thumbprint)
   }
    
    // MARK: - X5Chain Tests
    
    @Test func testX5ChainInitialization() async throws {
        guard let filePath = Bundle.module.path(forResource: "valid_certificate", ofType: "der", inDirectory: "data/x509") else {
            fatalError("File not found: valid_certificate.der")
        }
        let certificate = try Data(contentsOf: URL(fileURLWithPath: filePath))
        
        let chain = try X5Chain(certData: certificate)
        
        #expect(chain.certChain.subject.description.isEmpty == false)
    }
    
    @Test func testX5ChainVerificationPasses() async throws {
        guard let filePath = Bundle.module.path(forResource: "valid_certificate", ofType: "der", inDirectory: "data/x509") else {
            fatalError("File not found: valid_certificate.der")
        }
        let certificate = try Data(contentsOf: URL(fileURLWithPath: filePath))
        let chain = try X5Chain(certData: certificate, verify: true)
        
        #expect(chain.certChain.subject.description.isEmpty == false)
    }
    
    @Test func testX5ChainVerificationFails() async throws {
        guard let filePath = Bundle.module.path(forResource: "invalid_usage_certificate", ofType: "der", inDirectory: "data/x509") else {
            fatalError("File not found: invalid_usage_certificate.der")
        }
        let certificate = try Data(contentsOf: URL(fileURLWithPath: filePath))
        
        #expect(throws: CoseError.self) {
            let _ = try X5Chain(certData: certificate, verify: true)
        }
    }
    
    // MARK: - X5U Tests
    
    @Test func testX5UInitialization() async throws {
        let uri = "https://example.com/cert"
        let x5u = X5U(uri: uri)
        
        #expect(x5u.uri == uri)
    }
    
    @Test func testX5UEncoding() async throws {
        let uri = "https://example.com/cert"
        let x5u = X5U(uri: uri)
        
        #expect(x5u.encode() == uri)
    }
}
