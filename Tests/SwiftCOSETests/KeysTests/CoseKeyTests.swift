import Testing
import Foundation
import CBORCodable
@testable import SwiftCOSE

struct CoseKeyTests {

    // MARK: - Initialization Tests
    
    @Test
    func testCoseKeyInitialization() async throws {
        let keyDict: [AnyHashable: Any] = [
            KpKty(): KtyOKP(),
            KpAlg(): EdDSAAlgorithm(),
            KpKid(): Data([0x01, 0x02]),
            KpBaseIV(): Data([0x03, 0x04]),
            KpKeyOps(): [EncryptOp(), DecryptOp()]
        ]
        
        let coseKey = CoseKey(keyDict: keyDict)
        
        #expect(coseKey.kty == KtyOKP())
        #expect(coseKey.alg == EdDSAAlgorithm())
        #expect(coseKey.kid == Data([0x01, 0x02]))
        #expect(coseKey.baseIV == Data([0x03, 0x04]))
        #expect(coseKey.keyOps == [])
    }
    
    @Test
    func testCoseKeyFromDictionary() async throws {
        let verificationKeyData = "60545b786d3a6f903158e35aae9b86548a99bc47d4b0a6f503ab5e78c1a9bbfc"
        
        let coseKeyDict = [
            KpKty(): KtyOKP(),
            OKPKpCurve(): Ed25519Curve(),
            KpKeyOps(): [SignOp(), VerifyOp()],
            OKPKpX(): verificationKeyData
        ] as [AnyHashable : Any]

        let coseKey = try CoseKey.fromDictionary(coseKeyDict)

        #expect(coseKey.kty == KtyOKP())
    }
    
    @Test
    func testCoseKeyWithEmptyDict() async throws {
        let coseKey = CoseKey(keyDict: [:])
        
        #expect(coseKey.kty == nil)
        #expect(coseKey.alg == nil)
        #expect(coseKey.kid == nil)
        #expect(coseKey.baseIV == nil)
    }

    // MARK: - Key Operations Tests
    
    @Test
    func testKeyOpsSetAndGet() async throws {
        let coseKey = CoseKey(keyDict: [:])
        let keyOps: [KeyOps] = [EncryptOp(), DecryptOp()]
        
        coseKey.keyOps = keyOps
        
        #expect(coseKey.keyOps == keyOps)
    }
    
    @Test
    func testKeyOpsEmpty() async throws {
        let coseKey = CoseKey(keyDict: [KpKeyOps(): [EncryptOp(), DecryptOp()]])
        
        #expect(coseKey.keyOps.isEmpty)
    }
    
    // MARK: - Encode and Decode Tests
    
    @Test
    func testCoseKeyEncode() async throws {
        let keyDict: [AnyHashable: Any] = [
            KpKty(): KtyOKP(),
            KpAlg(): EdDSAAlgorithm(),
            KpKid(): Data([0x01, 0x02]),
            KpBaseIV(): Data([0x03, 0x04])
        ]
        
        let coseKey = CoseKey(keyDict: keyDict)
        let encoded = try coseKey.encode()
        
        #expect(encoded != nil)
        #expect(!encoded!.isEmpty)
    }
    
    @Test
    func testCoseKeyDecode() async throws {
        let keyDict: [AnyHashable: Any] = [
            KpKty(): KtyReserved(),
            KpAlg(): Direct(),
            KpBaseIV(): Data([0x03, 0x04]),
            KpKid(): Data([0x01, 0x02])
        ]
        
        let coseKey = CoseKey(keyDict: keyDict)
        let encoded = try coseKey.encode()!
        let decodedKey = try CoseKey.decode(encoded)
        
        #expect(decodedKey != nil)
        #expect(decodedKey!.kty == KtyReserved())
        #expect(decodedKey!.alg == Direct())
        #expect(decodedKey!.kid == Data([0x01, 0x02]))
    }
    
    @Test
    func testCoseKeyDecodeFromHex() async throws {
        let key = "a401010327200621582060545b786d3a6f903158e35aae9b86548a99bc47d4b0a6f503ab5e78c1a9bbfc"
        
        let decodedKey = try CoseKey.decode(Data(hex: key)) as! OKPKey
        let verificationKey = decodedKey.store[OKPKpX()] as! Data

        #expect(decodedKey.kty == KtyOKP())
        #expect(verificationKey == decodedKey.x)
    }
    
    @Test
    func testCoseKeyDecodeNormalizesIntegerKeys() async throws {
        // Regression: on swift-corelibs-foundation (Linux/Windows) the CBOR
        // map keys come back as UInt64, which do not match Int-keyed lookups
        // via NSNumber bridging. CoseKey.decode must normalize them to Int
        // so that fromDictionary's `received[kpKty.identifier]` lookup
        // (where identifier is Int) succeeds.
        let key = "a401010327200621582060545b786d3a6f903158e35aae9b86548a99bc47d4b0a6f503ab5e78c1a9bbfc"

        let decoded = try CoseKey.decode(Data(hex: key))

        #expect(decoded != nil)
        #expect(decoded!.kty == KtyOKP())
        // The store must be keyed by Int (not UInt64/Int64) so subsequent
        // lookups by KeyParam.identifier (which is Int) hit.
        for k in decoded!.store.keys {
            #expect(!(k.base is UInt64), "decoded store key \(k) should not be UInt64")
            #expect(!(k.base is Int64), "decoded store key \(k) should not be Int64")
        }
    }

    @Test
    func testDecodeInvalidData() async throws {
        let invalidData = Data([0x01, 0x02])
        
        #expect(throws: CoseError.self) {
            let _ = try CoseKey.decode(invalidData)
        }
    }
    
    // MARK: - Base64 Encoding/Decoding Tests
    
    @Test
    func testBase64Encode() async throws {
        let data = Data([0x12, 0x34])
        let encoded = CoseKey.base64encode(data)
        
        #expect(encoded == "EjQ=")
    }
    
    @Test
    func testBase64Decode() async throws {
        let encodedString = "EjQ="
        let decoded = CoseKey.base64decode(encodedString)
        
        #expect(decoded == Data([0x12, 0x34]))
    }
    
    @Test
    func testBase64DecodeInvalid() async throws {
        let invalidString = "Invalid!Base64"
        let decoded = CoseKey.base64decode(invalidString)
        
        #expect(decoded == nil)
    }
    
    // MARK: - Dictionary Operations
    
    @Test
    func testSubscriptAccess() async throws {
        let keyDict: [AnyHashable: Any] = [KpKty(): KtyReserved()]
        let coseKey = CoseKey(keyDict: keyDict)
        
        #expect(coseKey[KpKty()] as? KTY == KtyReserved())
    }
    
    @Test
    func testSubscriptSet() async throws {
        let coseKey = CoseKey(keyDict: [:])
        coseKey[KpKty()] = KtyReserved()
        
        #expect(coseKey[KpKty()] as? KTY == KtyReserved())
    }
    
    @Test
    func testRemoveItem() async throws {
        let keyDict: [AnyHashable: Any] = [KpKty(): KtyReserved()]
        let coseKey = CoseKey(keyDict: keyDict)
        
        coseKey.removeItem(forKey: KpKty())
        #expect(coseKey[KpKty()] == nil)
    }
    
    @Test
    func testContainsKey() async throws {
        let keyDict: [AnyHashable: Any] = [KpKty(): KtyReserved()]
        let coseKey = CoseKey(keyDict: keyDict)
        
        #expect(coseKey.contains(KpKty()))
    }
    
    @Test
    func testStore() async throws {
        let keyDict: [AnyHashable: Any] = [KpKty(): KtyReserved(), KpAlg(): Direct()]
        let coseKey = CoseKey(keyDict: keyDict)
        
        var count = 0
        for _ in coseKey.store {
            count += 1
        }
        
        #expect(count == 2)
    }
    
    @Test
    func testKeyCount() async throws {
        let keyDict: [AnyHashable: Any] = [
            KpKty(): KtyReserved(),
            KpAlg(): Direct(),
            KpKid(): Data([0x01])
        ]
        let coseKey = CoseKey(keyDict: keyDict)
        
        #expect(coseKey.count == 3)
    }
}
