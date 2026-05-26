import Testing
import Foundation
import CBORCodable
import OrderedCollections
@testable import SwiftCOSE

struct SignCommonTests {
    
    // MARK: - Initialization Tests
    
    @Test func testSignCommonInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): Es256(),
            IV(): Data([0x01, 0x02, 0x03, 0x04])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/sign-cbor"
        ]
        
        let payload = Data("Sign Payload".utf8)
        let externalAAD = Data("Sign AAD".utf8)
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let key = try EC2Key.generateKey(curve: curve)
        
        let signMessage = SignCommon(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: key
        )
        
        #expect(signMessage.phdr.count == 2, "Protected header should contain 2 attributes.")
        #expect(signMessage.uhdr.count == 1, "Unprotected header should contain 1 attribute.")
        #expect(signMessage.payload == payload, "Payload should match the initialized value.")
        #expect(signMessage.externalAAD == externalAAD, "External AAD should match the initialized value.")
        #expect(signMessage.key === key, "Key should match the initialized key.")
    }
    
    // MARK: - Key Verification Tests
        
    @Test func testKeyVerificationWithEC2Key() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.p256)
        let ec2Key = try EC2Key.generateKey(curve: curve)
        
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): Es256()]
        let signMessage = SignCommon(
            phdr: phdr,
            uhdr: [:],
            payload: Data(),
            externalAAD: Data(),
            key: ec2Key
        )
        
        #expect(throws: Never.self) {
            try signMessage.keyVerification(alg: Es256(), ops: SignOp())
        }
    }
    
    @Test func testKeyVerificationWithOKPKey() async throws {
        let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.x25519)
        let okpKey = try OKPKey.generateKey(curve: curve)
        
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): EdDSAAlgorithm()]
        let signMessage = SignCommon(
            phdr: phdr,
            uhdr: [:],
            payload: Data(),
            externalAAD: Data(),
            key: okpKey
        )
        
        #expect(throws: Never.self) {
            try signMessage.keyVerification(alg: EdDSAAlgorithm(), ops: VerifyOp())
        }
    }
    
    @Test func testKeyVerificationWithRSAKey() async throws {
        let rsaKey = try RSAKey.generateKey(keyBits: 1024)
        
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): Ps256()]
        let signMessage = SignCommon(
            phdr: phdr,
            uhdr: [:],
            payload: Data(),
            externalAAD: Data(),
            key: rsaKey
        )
        
        #expect(throws: Never.self) {
            try signMessage.keyVerification(alg: Ps256(), ops: SignOp())
        }
    }
    
    @Test func testKeyVerificationWithNilKey() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [Algorithm(): Es256()]
        let signMessage = SignCommon(
            phdr: phdr,
            uhdr: [:],
            payload: Data(),
            externalAAD: Data(),
            key: nil
        )
        
        #expect(throws: CoseError.self) {
            try signMessage.keyVerification(alg: Es256(), ops: SignOp())
        }
    }
}
