import Testing
import Foundation
import UncommonCrypto
import CryptoKit
import P256K
@testable import SwiftCOSE

struct CurveTypeTests {
    // Test that all cases are covered
    @Test func testCurveTypeCaseCount() async throws {
        #expect(CurveType.allCases.count == 8)
    }
    
    @Test func testKeyTypeCaseCount() async throws {
        #expect(KeyType.allCases.count == 3)
    }
    
    // Test raw values of CurveType
    @Test func testCurveTypeRawValues() async throws {
        #expect(CurveType.SECP256K1.rawValue == 0)
        #expect(CurveType.SECP256R1.rawValue == 1)
        #expect(CurveType.SECP384R1.rawValue == 2)
        #expect(CurveType.SECP521R1.rawValue == 3)
        #expect(CurveType.ED25519.rawValue == 4)
        #expect(CurveType.ED448.rawValue == 5)
        #expect(CurveType.X25519.rawValue == 6)
        #expect(CurveType.X448.rawValue == 7)
    }

    // Test raw values of KeyType
    @Test func testKeyTypeRawValues() async throws {
        #expect(KeyType.ktyEC2.rawValue == 0)
        #expect(KeyType.ktyOKP.rawValue == 1)
        #expect(KeyType.none.rawValue == 2)
    }
    
    // MARK: - Individual CoseCurve Tests
    @Test("Test All Cose Curves", arguments: CoseCurveIdentifier.allCases)
    func testCoseCurve(_ curveId: CoseCurveIdentifier) async throws {
        let curve1 = try CoseCurve.fromId(for: curveId)
        let curve2 = try CoseCurve.fromId(for: curve1.fullname!)
        let curve3 = try CoseCurve.fromId(for: curveId.rawValue)
        
        #expect(curve1 == curve2)
        #expect(curve2 == curve3)
        #expect(curve1.identifier == curveId.rawValue)
        #expect(curve1.identifier == CoseCurveIdentifier.fromFullName(curve1.fullname!)?.rawValue)
    }
    
    
}
