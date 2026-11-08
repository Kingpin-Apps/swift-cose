import Foundation
import CBORCodable
import OrderedCollections

public struct PartyInfo {
    var identity: Data? = nil
    var nonce: Data? = nil
    var other: Data? = nil

    /// RFC 9053, section 5.2: each field is a byte string, or nil when absent.
    func encode() -> [CBOR] {
        return [
            identity.map { CBOR.byteString($0) } ?? CBOR.null,
            nonce.map { CBOR.byteString($0) } ?? CBOR.null,
            other.map { CBOR.byteString($0) } ?? CBOR.null
        ]
    }
}

public struct SuppPubInfo {
    private var _keyDataLength: Int
    var protected: OrderedDictionary<CoseHeaderAttribute, Any> = [:]
    /// The recipient's protected header exactly as encoded in the message.
    /// When nil, `protected` is encoded instead.
    var protectedEncoded: Data? = nil
    var other: Data = Data()
    
    /// The length of the derived key in bytes.
    /// Set the length of the derived key. Must be 16, 24 or 32 bytes (AES), or 48 or 64 bytes (HMAC).
    var keyDataLength: Int  {
        get {
            return _keyDataLength
        }
        set {
            guard [16, 24, 32, 48, 64].contains(newValue) else {
                fatalError("Not a valid key length: \(newValue)")
            }
            _keyDataLength = newValue
        }
    }

    init(keyDataLength: Int, protected: OrderedDictionary<CoseHeaderAttribute, Any> = [:], protectedEncoded: Data? = nil, other: Data = Data()) throws {
        guard [16, 24, 32, 48, 64].contains(keyDataLength) else {
            throw CoseError.valueError("Not a valid key length: \(keyDataLength)")
        }
        self._keyDataLength = keyDataLength
        self.protected = protected
        self.protectedEncoded = protectedEncoded
        self.other = other
    }
    
    ///  Encodes the supplementary public information.
    ///
    /// RFC 9053, section 5.2:
    /// `[keyDataLength: uint, protected: empty_or_serialized_map, ? other: bstr]`
    /// - Returns: A CBOR array representing the supplementary public information.
    func encode() throws -> [CBOR] {
        let protectedBytes: Data
        if let protectedEncoded {
            protectedBytes = protectedEncoded
        } else if protected.isEmpty {
            protectedBytes = Data()
        } else {
            protectedBytes = try CBORSerialization.data(from: .map(try protected.mapKeysToCbor()))
        }
        
        var info: [CBOR] = [
            CBOR.unsignedInt(UInt64(keyDataLength * 8)),
            CBOR.byteString(protectedBytes)
        ]
        
        if !other.isEmpty {
            info.append(CBOR.byteString(other))
        }
        return info
    }
}

public struct CoseKDFContext {
    var algorithm: CoseAlgorithm
    var suppPubInfo: SuppPubInfo
    var partyUInfo: PartyInfo = PartyInfo()
    var partyVInfo: PartyInfo = PartyInfo()
    var suppPrivInfo: Data = Data()

    func encode() throws -> Data {
        let algCBOR: CBOR
        if let algId = algorithm.identifier {
            algCBOR = CBOR(algId)
        } else if let fullname = algorithm.fullname {
            algCBOR = CBOR(fullname)
        } else {
            throw CoseError.valueError("The algorithm must have an identifier or fullname.")
        }
        
        var context: [CBOR] = [
            algCBOR,
            CBOR.array(partyUInfo.encode()),
            CBOR.array(partyVInfo.encode()),
            CBOR.array(try suppPubInfo.encode())
        ]

        if !suppPrivInfo.isEmpty {
            context.append(CBOR.byteString(suppPrivInfo))
        }

        return try CBORSerialization.data(from: .array(context))
    }
}
