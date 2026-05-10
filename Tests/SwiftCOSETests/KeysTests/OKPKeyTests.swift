import Testing
import Foundation
import CryptoKit
import P256K
@testable import SwiftCOSE

struct OKPKeyTests {
    
    // MARK: - Test Initialization
    
    @Test func testOKPKeyInitialization() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.ed25519)
        
        let privateKey: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let key = try OKPKey(
            curve: curve,
            x: publicKey.rawRepresentation,
            d: privateKey.rawRepresentation
        )
        
        #expect(key.curve == curve)
        #expect(key.x == publicKey.rawRepresentation)
        #expect(key.d == privateKey.rawRepresentation)
    }
    
    // MARK: - Test Key Generation
    
    @Test func testOKPKeyGeneration() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.ed25519)
        let key = try OKPKey.generateKey(curve: curve)
        
        #expect(key.curve == curve)
        #expect(key.x!.count > 0)
        #expect(key.d!.count > 0)
    }
    
    // MARK: - Test Unsupported Curve
    
    @Test func testUnsupportedCurve() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.reserved)
        
        #expect(throws: CoseError.self) {
            _ = try OKPKey.generateKey(curve: curve)
        }
    }
    
    // MARK: - Test Key Operations
    
    @Test func testOKPKeyOperations() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.ed25519)
        let key = try OKPKey.generateKey(curve: curve)
        
        let signOp = SignOp()
        let verifyOp = VerifyOp()
        
        key.keyOps = [signOp, verifyOp]
        
        #expect(key.keyOps.contains { $0 is SignOp })
        #expect(key.keyOps.contains { $0 is VerifyOp })
    }
    
    // MARK: - Test From Dictionary
    
    @Test func testFromDictionary() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.ed25519)
        
        let privateKey: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let keyDict: [AnyHashable: Any] = [
            OKPKpCurve(): curve.identifier!,
            OKPKpX(): publicKey.rawRepresentation,
            OKPKpD(): privateKey.rawRepresentation
        ]
        
        let key = try OKPKey.fromDictionary(keyDict)
        
        #expect(key.curve == curve)
        #expect(key.x == publicKey.rawRepresentation)
        #expect(key.d == privateKey.rawRepresentation)
    }
    
    // MARK: - Test Key Deletion
    
    @Test func testOKPKeyDeletion() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.ed25519)
        let key = try OKPKey.generateKey(curve: curve)
        
        try key.delete(key: OKPKpD())
        
        #expect(key.d == nil)
        #expect(key.x!.count > 0)
    }
    
    // MARK: - Test Invalid Deletion
    
    @Test func testInvalidKeyDeletion() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.ed25519)
        let key = try OKPKey.generateKey(curve: curve)
        
        #expect(throws: CoseError.self) {
            try key.delete(key: OKPKpCurve())
        }
    }
    
    // MARK: - Test Description
    
    @Test func testDescription() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.ed25519)
        let key = try OKPKey.generateKey(curve: curve)
        
        let description = key.description
        
        #expect(description.contains("COSE_Key"))
        #expect(description.contains("OKPKey"))
    }
}
