import Testing
import Foundation
import PotentCBOR
import OrderedCollections
@testable import SwiftCOSE

struct CoseBaseTests {
    
    // MARK: - Initialization Tests
    
    @Test func testCoseBaseInitialization() async throws {
        let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): A128GCM(),
            IV(): Data([0x01, 0x02, 0x03, 0x04])
        ]
        
        let uhdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
            ContentType(): "application/json"
        ]
        
        let coseBase = CoseBase(phdr: phdr, uhdr: uhdr)
        
        #expect(coseBase.phdr.count == 2, "Protected header should have 2 attributes.")
        #expect(coseBase.uhdr.count == 1, "Unprotected header should have 1 attribute.")
        #expect(
            coseBase.phdr[Algorithm()] is A128GCM,
            "Algorithm in protected header should be A128GCM."
        )
        #expect(
            coseBase.uhdr[ContentType()] as? String == "application/json",
            "ContentType in unprotected header should be 'application/json'."
        )
    }
    
    @Test func testCoseBaseEmptyInitialization() async throws {
        let coseBase = CoseBase()
        
        #expect(coseBase.phdr.isEmpty, "Protected header should be empty.")
        #expect(coseBase.uhdr.isEmpty, "Unprotected header should be empty.")
    }
    
    // MARK: - From Cose Object Tests
    
    @Test func testFromCoseObject() async throws {
        let coseArray: CBOR.Array = [
            CBOR.byteString(Data()),  // Zero-length protected header
            CBOR.map([
                CBOR.simple(1): CBOR(Direct().identifier!) // Algorithm
            ]),
            CBOR.byteString(Data())  // Zero-length ciphertext
        ]
        
        let coseBase = try CoseBase.fromCoseObject(coseObj: coseArray)
        
        #expect(coseBase.phdr.isEmpty)
        #expect(coseBase.uhdr[Algorithm()] as? CoseAlgorithm == Direct())
    }
    
    // MARK: - Protected Header Tests
    
    @Test func testUpdateProtectedHeader() async throws {
        let coseBase = CoseBase()
        coseBase.updateProtectedHeader(with: [
            Algorithm(): A256GCM()
        ])
        
        #expect(coseBase.phdr.count == 1, "Protected header should have 1 attribute.")
        #expect(
            coseBase.phdr[Algorithm()] is A256GCM,
            "Algorithm in protected header should be A256GCM."
        )
        
        coseBase.updateProtectedHeader(with: [
            IV(): Data([0x05, 0x06, 0x07, 0x08])
        ])
        
        #expect(
            coseBase.phdr[IV()] as? Data == Data([0x05, 0x06, 0x07, 0x08]),
            "IV should be correctly updated in protected header."
        )
    }
    
    @Test func testProtectedHeaderEncoding() async throws {
        let coseBase = CoseBase()
        coseBase.updateProtectedHeader(with: [
            Algorithm(): A128GCM(),
            IV(): Data([0x09, 0x0A, 0x0B, 0x0C])
        ])
        
        let encoded = coseBase.phdrEncoded
        
        #expect(!encoded.isEmpty, "Encoded protected header should not be empty.")
        
        let decoded = try CBORSerialization.cbor(from: encoded)
        let decodedMap = decoded.mapValue!
        
        #expect(
            decodedMap[1] != nil,
            "Algorithm should exist in encoded protected header."
        )
    }
    
    // MARK: - Unprotected Header Tests
    
    @Test func testUpdateUnprotectedHeader() async throws {
        let coseBase = CoseBase()
        coseBase.updateUnprotectedHeader(with: [
            ContentType(): "text/plain"
        ])
        
        #expect(coseBase.uhdr.count == 1, "Unprotected header should have 1 attribute.")
        #expect(
            coseBase.uhdr[ContentType()] as? String == "text/plain",
            "ContentType should be 'text/plain'."
        )
    }
    
    @Test func testUnprotectedHeaderEncoding() async throws {
        let coseBase = CoseBase()
        coseBase.updateUnprotectedHeader(with: [
            IV(): Data([0x0D, 0x0E, 0x0F, 0x10])
        ])
        
        let encoded = coseBase.uhdrEncoded
        
        #expect(encoded.count == 1, "Unprotected header should have 1 encoded attribute.")
        #expect(
            encoded[IV()] as? Data == Data([0x0D, 0x0E, 0x0F, 0x10]),
            "IV should be correctly encoded in unprotected header."
        )
    }
    
    @Test func testConflictingInitialization() async throws {
        #expect(throws: CoseError.self) {
            let _ = try CoseBase(
                phdr: [Algorithm(): A128GCM()],
                phdrEncoded: Data([0x01, 0x02])
            )
        }
    }
    
    @Test func testGetAttrFromHeaders() async throws {
        let coseBase = CoseBase()
        coseBase.updateProtectedHeader(with: [
            Algorithm(): A256GCM()
        ])
        coseBase.updateUnprotectedHeader(with: [
            ContentType(): "application/cbor"
        ])
        
        let algo = try coseBase.getAttr(Algorithm()) as? A256GCM
        let contentType = try coseBase.getAttr(ContentType()) as? String
        
        #expect(algo != nil, "Algorithm should be retrievable from headers.")
        #expect(contentType == "application/cbor", "ContentType should be retrievable as 'application/cbor'.")
    }
    
    @Test func testHdrRepr() async throws {
        let coseBase = CoseBase()
        coseBase.updateProtectedHeader(with: [
            Algorithm(): A256GCM()
        ])
        coseBase.updateUnprotectedHeader(with: [
            ContentType(): "application/cbor"
        ])
        
        let hdrRepr = coseBase.hdrRepr()

        #expect(!hdrRepr.phdr.isEmpty, "Protected header representation should not be empty.")
        #expect(!hdrRepr.uhdr.isEmpty, "Unprotected header representation should not be empty.")
    }
        
}
