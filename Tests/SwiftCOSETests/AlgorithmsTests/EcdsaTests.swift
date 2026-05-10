import Testing
import Foundation
@testable import SwiftCOSE

struct EcdsaAlgorithmTests {
    
    // MARK: - EcdsaAlgorithm Tests
    @Test("Test Ecdsa Algorithm Sign and Verify", arguments: zip([
        CoseAlgorithmIdentifier.es256,
        .es384,
        .es512
    ], [
        CoseCurveIdentifier.p256,
        .p384,
        .p521
    ]))
    func testEcdsaSignAndVerify(_ algId: CoseAlgorithmIdentifier, _ curveId: CoseCurveIdentifier) async throws {
        let curve = try CoseCurve.fromId(for: curveId)
        
        // Generate keypair for testing
        let keyPair = try EC2Key.generateKey(curve: curve)
        
        // Sample data to sign
        let data = "Hello, ECDSA!".data(using: .utf8)!
        
        // Perform signing
        let ecdsa = try EcdsaAlgorithm.fromId(
            for: algId
        ) as! EcdsaAlgorithm
        let signature = try ecdsa.sign(key: keyPair, data: data)

        #expect(
            !signature.isEmpty,
            "Signature should not be empty"
        )
        
        // Verify signature
        let isValid = try ecdsa.verify(key: keyPair, data: data, signature: signature)
        
        #expect(
            isValid,
            "Signature verification should succeed"
        )
        
        // Test with tampered data
        let tamperedData = "Hello, Tampered!".data(using: .utf8)!
        let isTamperedValid = try ecdsa.verify(
            key: keyPair,
            data: tamperedData,
            signature: signature
        )
        
        #expect(
            !isTamperedValid,
            "Tampered data should not verify"
        )
    }
}
