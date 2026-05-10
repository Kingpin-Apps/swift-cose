import Testing
import Foundation
import CryptoKit
import P256K
@testable import SwiftCOSE

struct EC2KeyTests {
    
    // MARK: - Test Initialization
    
    @Test func testEC2KeyInitialization() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        
        let privateKey: P256.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: curve.curveType!)
    
        let (curveType, xData, yData, dData) = try deriveNumbers(from: privateKey)
        
        let key = try EC2Key(curve: curve, x: xData, y: yData, d: dData)
        
        #expect(key.curve == curve)
        #expect(key.curve.curveType == curveType)
        #expect(key.x == xData)
        #expect(key.y == yData)
        #expect(key.d == dData)
    }
    
    // MARK: - Test Key Generation
    
    @Test func testKeyGeneration() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        #expect(key.curve == curve)
        #expect(key.x!.count > 0)
        #expect(key.y!.count > 0)
        #expect(key.d!.count > 0)
    }
    
    // MARK: - Test Unsupported Curve
    
    @Test func testUnsupportedCurve() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.reserved)
        
        #expect(throws: CoseError.self) {
            _ = try EC2Key.generateKey(curve: curve)
        }
    }
    
    // MARK: - Test Key Operations
    
    @Test func testKeyOperations() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        let signOp = SignOp()
        let verifyOp = VerifyOp()
        
        key.keyOps = [signOp, verifyOp]
        
        #expect(key.keyOps.contains { $0 is SignOp })
        #expect(key.keyOps.contains { $0 is VerifyOp })
    }
    
    // MARK: - Test From Dictionary
    
    @Test func testFromDictionary() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        
        let privateKey: P256.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: curve.curveType!)
    
        let (_, xData, yData, dData) = try deriveNumbers(from: privateKey)

        let keyDict: [AnyHashable: Any] = [
            EC2KpCurve(): curve.identifier!,
            EC2KpX(): xData,
            EC2KpY(): yData!,
            EC2KpD(): dData!
        ]
        
        let key = try EC2Key.fromDictionary(keyDict)
        
        #expect(key.curve == curve)
        #expect(key.x == xData)
        #expect(key.y == yData)
        #expect(key.d == dData)
    }
    
    // MARK: - Test Key Deletion
    
    @Test func testKeyDeletion() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        try key.delete(key: EC2KpD())
        
        #expect(key.d == nil)
        #expect(key.x!.count > 0)
        #expect(key.y!.count > 0)
    }
    
    // MARK: - Test Invalid Deletion
    
    @Test func testInvalidKeyDeletion() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        #expect(throws: CoseError.self) {
            try key.delete(key: EC2KpCurve())
        }
    }
    
    // MARK: - Test Description
    
    @Test func testDescription() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        let description = key.description
        
        #expect(description.contains("COSE_Key"))
        #expect(description.contains("EC2Key"))
    }
}
