import Foundation
import CBORCodable
import OrderedCollections

public enum CoseMessageIdentifier: Int, CaseIterable, Sendable {
    case encrypt0 = 16
    case encrypt = 96
    case mac0 = 17
    case mac = 97
    case sign1 = 18
    case sign = 98
    
    /// Returns the appropriate `CoseMessageIdentifier` for the given fullname.
    /// - Parameter fullName: The string fullname of the algorithm.
    /// - Returns: The corresponding `CoseMessageIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullName: String) -> CoseMessageIdentifier? {
        switch fullName {
            case "COSE_Encrypt0":
                return .encrypt0
            case "COSE_Encrypt":
                return .encrypt
            case "COSE_Mac0":
                return .mac0
            case "COSE_Mac":
                return .mac
            case "COSE_Sign1":
                return .sign1
            case "COSE_Sign":
                return .sign
            default:
                return nil
        }
    }
}

/// Parent class of all COSE message types.
public class CoseMessage: CoseBase, CustomStringConvertible {
    
    // MARK: - Abstract Methods
    public var cborTag: Int {
        fatalError("cborTag must be implemented in subclasses.")
    }
    
    public var description: String {
        fatalError("Must be overridden in subclass.")
    }
    
    // MARK: - Properties

    /// Key associated with the COSE message.
    private var _key: CoseKey?

    /// Payload of the COSE message, which can be plaintext or ciphertext.
    private var _payload: Data?
    
    /// External Additional Authenticated Data (AAD).
    public var externalAAD: Data {
        get {
            return _externalAAD
        }
        set {
            _externalAAD = newValue
        }
    }
    private var _externalAAD: Data = Data()

    /// The key associated with the COSE message.
    public var key: CoseKey? {
        get {
            return _key
        }
        set {
            if let newKey = newValue {
                guard newKey is CoseSymmetricKey || newKey is EC2Key || newKey is OKPKey || newKey is RSAKey else {
                    fatalError("Unknown key type: \(type(of: newKey))")
                }
            }
            _key = newValue
        }
    }

    /// The payload of the COSE message.
    public override var payload: Data? {
        get {
            return _payload
        }
        set {
            _payload = newValue
        }
    }

    // MARK: - Initialization

    /// Initializes a new instance of the CoseMessage class.
    ///
    /// - Parameters:
    ///   - phdr: Protected header dictionary (optional).
    ///   - uhdr: Unprotected header dictionary (optional).
    ///   - payload: The payload of the COSE message (optional).
    ///   - externalAAD: External AAD for the COSE message (default: empty data).
    ///   - key: Key associated with the COSE message (optional).
    public init(phdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                uhdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                payload: Data? = nil,
                externalAAD: Data = Data(),
                key: CoseKey? = nil) {
        super.init(phdr: phdr, uhdr: uhdr)
        self.payload = payload
        self.externalAAD = externalAAD
        self.key = key
    }

    
    // MARK: - Methods
    public static func fromId(for attribute: Any) throws -> CoseMessage.Type {
        switch attribute {
            case let id as Int:
                // If the identifier is an Int, convert it to CoseMessageIdentifier
                guard let messageId = CoseMessageIdentifier(rawValue: id) else {
                    throw CoseError.invalidMessage("Unknown identifier")
                }
                return getInstance(for: messageId)
                
            case let name as String:
                // If the identifier is a String, attempt to match it to a CoseMessageIdentifier
                guard let messageId = CoseMessageIdentifier.fromFullName(name) else {
                    throw CoseError.invalidMessage("Unknown fullname")
                }
                return getInstance(for: messageId)
                
            case let messageId as CoseMessageIdentifier:
                // If the identifier is already a CoseMessageIdentifier, get the instance directly
                return getInstance(for: messageId)
                
            default:
                throw CoseError.invalidMessage("Unsupported identifier type. Must be Int, String, or CoseMessageIdentifier")
        }
    }
    
    public class func getInstance(for identifier: CoseMessageIdentifier) -> CoseMessage.Type {
        switch identifier {
            case .encrypt0:
                return Enc0Message.self
            case .encrypt:
                return EncMessage.self
            case .mac0:
                return Mac0Message.self
            case .mac:
                return MacMessage.self
            case .sign1:
                return Sign1Message.self
            case .sign:
                return  SignMessage.self
        }
    }
    
    /// Function to return an initialized COSE message object.
    /// - Parameter coseObj: The CBOR object to decode.
    /// - Returns: The decoded COSE message.
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> CoseMessage {
        let baseMsg = try super.fromCoseObject(coseObj: coseObj)
        baseMsg.payload = coseObj.last?.byteStringValue
        return CoseMessage(
            phdr: baseMsg.phdr,
            uhdr: baseMsg.uhdr,
            payload: baseMsg.payload
        )
    }
    
    /// Decode received COSE message based on the CBOR tag.
    ///
    /// If called on CoseMessage, this function can decode any supported
    /// message type. Otherwise, if called on a sub-class of CoseMessage,
    /// only messages of that type will be allowed to be decoded.
    ///
    /// - Parameters:
    ///   - type: The type of COSE message to decode.
    ///   - received: COSE messages encoded as bytes
    /// - Returns: The decoded COSE message.
    public class func decode<T: CoseMessage>(_ type: T.Type, from received: Data) throws -> T {
        let cborMsg = try CBORSerialization.cbor(from: received)
        
        let cborObj: CBOR
        if case let .tagged(_, cborData) = cborMsg {
            cborObj = cborData
        } else {
            throw CoseError.invalidMessage("Message is not tagged.")
        }
        
        if let messageType = cborObj.arrayValue {
            do {
                let decoded = try T.fromCoseObject(
                    coseObj: messageType
                )
                return decoded as! T
            } catch {
                throw CoseError.invalidMessage("Unable to decode message.")
            }
        } else {
            throw CoseError.invalidMessage("Invalid message structure.")
        }
    }

    public func encode(message: [CBOR], tag: Bool = true) throws -> Data {
        if tag {
            return try CBORSerialization
                .data(
                    from: CBOR
                        .tagged(
                            UInt64(cborTag),
                            CBOR.array(message)
                        )
                )
        } else {
            return try CBORSerialization.data(from: .array(message))
        }
    }

    public func baseStructure(_ structure: inout [CBOR]) {
        if phdr.isEmpty {
            structure.append(CBOR.byteString(Data()))
        } else {
            structure.append(CBOR.byteString(phdrEncoded))
        }

        structure.append(CBOR.byteString(externalAAD))
    }
}
