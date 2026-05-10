import Testing
import Foundation
@testable import SwiftCOSE

struct EdDSATests {
    
    // MARK: - EdDSA Tests
    @Test("Test EdDSA Algorithm Sign and Verify", arguments: [
        CoseCurveIdentifier.ed25519,
        .ed448,
    ])
    func testEdDSASignAndVerify(_ curveId: CoseCurveIdentifier) async throws {
        let curve = try CoseCurve.fromId(for: curveId)
        
        // Generate keypair for testing
        let keyPair = try OKPKey.generateKey(curve: curve)
        
        // Sample data to sign
        let data = "Hello, EdDSA!".data(using: .utf8)!
        
        // Perform signing
        let eddsa = try CoseAlgorithm.fromId(
            for: CoseAlgorithmIdentifier.edDSA
        ) as! EdDSAAlgorithm
        let signature = try eddsa.sign(key: keyPair, data: data)

        #expect(
            !signature.isEmpty,
            "Signature should not be empty"
        )
        
        // Verify signature
        let isValid = try eddsa.verify(key: keyPair, data: data, signature: signature)
        
        #expect(
            isValid,
            "Signature verification should succeed"
        )
        
        // Test with tampered data
        let tamperedData = "Hello, Tampered!".data(using: .utf8)!
        let isTamperedValid = try eddsa.verify(key: keyPair, data: tamperedData, signature: signature)
        
        #expect(
            !isTamperedValid,
            "Tampered data should not verify"
        )
    }
}
