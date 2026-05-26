import Foundation
import CBORCodable
import OrderedCollections

public struct PartyInfo {
    var identity: Data? = nil
    var nonce: Data? = nil
    var other: Data? = nil

    func encode() -> [CBOR] {
        return [
            CBOR(identity ?? Data()),
            CBOR(nonce ?? Data()),
            CBOR(other ?? Data())
        ]
    }
}

public struct SuppPubInfo {
    private var _keyDataLength: Int
    var protected: OrderedDictionary<CoseHeaderAttribute, Any> = [:]
    var other: Data = Data()
    
    /// The length of the derived key in bytes.
    /// Set the length of the derived key. Must be of length 16, 24 or 32 bytes.
    var keyDataLength: Int  {
        get {
            return _keyDataLength
        }
        set {
            guard [16, 24, 32].contains(newValue) else {
                fatalError("Not a valid key length: \(newValue)")
            }
            _keyDataLength = newValue
        }
    }

    init(keyDataLength: Int, protected: OrderedDictionary<CoseHeaderAttribute, Any> = [:], other: Data = Data()) throws {
        guard [16, 24, 32].contains(keyDataLength) else {
            throw CoseError.valueError("Not a valid key length: \(keyDataLength)")
        }
        self._keyDataLength = keyDataLength
        self.protected = protected
        self.other = other
    }
    
    ///  Encodes the supplementary public information.
    /// - Returns: A CBOR array representing the supplementary public information.
    func encode() throws -> [CBOR] {
        var info: [CBOR] = [
            CBOR.unsignedInt(UInt64(keyDataLength * 8)),
            CBOR.map(protected.mapKeysToCbor)
        ]
        
        if !other.isEmpty {
            do {
                info.append(try CBORSerialization.cbor(from: other))
            } catch {
                throw CoseError.valueError("Failed to encode `other` data: \(error)")
            }
        }
        return info
    }
}

public struct CoseKDFContext {
    var algorithm: EncAlgorithm
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
            context.append(try! CBORSerialization.cbor(from: suppPrivInfo))
        }

        return try CBORSerialization.data(from: .array(context))
    }
}
