import Foundation
import CBORCodable
import OrderedCollections


/// Base class for all COSE Recipient types
public class CoseRecipient: CoseMessage {
    
    // MARK: - Properties
    // Context for the recipient
    public var context: String = ""
    
    // Recipients array
    public var recipients: [CoseRecipient] {
        get {
            return _recipients
        }
        set {
            _recipients = newValue
        }
    }
    private var _recipients: [CoseRecipient] = []
    
    // MARK: - Abstract Methods
    /// Decodes a COSE recipient.
    ///
    /// Without this override, `SomeRecipient.fromCoseObject(coseObj:)` would
    /// pick `CoseMessage`'s overload (it has no defaulted argument) and skip
    /// the recipient's own checks. Every call now goes through
    /// ``fromCoseObject(coseObj:context:)`` of the class it is made on.
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> CoseRecipient {
        return try fromCoseObject(coseObj: coseObj, context: nil)
    }
    
    public class func fromCoseObject(coseObj: [CBOR], context: String? = nil) throws -> CoseRecipient {
        // COSE_recipient = [protected, unprotected, ciphertext, ? recipients]
        guard coseObj.count == 3 || coseObj.count == 4 else {
            throw CoseError.invalidMessage("A COSE recipient must have three or four elements.")
        }
        let baseMsg = try super.fromCoseObject(coseObj: Array(coseObj.prefix(3)))
        
        var nested: [CoseRecipient] = []
        if coseObj.count == 4 {
            guard let recipientArray = coseObj[3].arrayValue else {
                throw CoseError.invalidMessage("Nested recipients must be an array.")
            }
            for recipient in recipientArray {
                guard let recipient = recipient.arrayValue, recipient.count >= 3 else {
                    throw CoseError.valueError("Invalid recipient")
                }
                nested.append(
                    try createRecipient(recipient: recipient, context: "Rec_Recipient")
                )
            }
        }
        
        let msg = CoseRecipient(
            uhdr: baseMsg.uhdr,
            payload: baseMsg.payload ?? Data(),
            externalAAD: baseMsg.externalAAD,
            key: baseMsg.key,
            recipients: nested
        )
        msg.copyProtectedHeader(from: baseMsg)
        if let context {
            msg.context = context
        }
        return msg
    }
    
    /// Abstract method to compute CEK
    public func computeCEK(targetAlgorithm: EncAlgorithm, ops: String) throws -> CoseSymmetricKey? {
        throw CoseError.unsupportedRecipient("\(type(of: self)) cannot compute a content key.")
    }
    
    /// Computes the content key for any target algorithm: a content
    /// encryption algorithm for COSE_Encrypt or a MAC algorithm for COSE_Mac.
    /// The recipient classes that derive or wrap keys override this; the
    /// public `computeCEK(targetAlgorithm:ops:)` forwards to it.
    func deriveCEK(targetAlgorithm: CoseAlgorithm, ops: String) throws -> CoseSymmetricKey? {
        guard let encAlgorithm = targetAlgorithm as? EncAlgorithm else {
            throw CoseError.unsupportedRecipient("\(type(of: self)) cannot compute a key for \(String(describing: targetAlgorithm.fullname)).")
        }
        return try computeCEK(targetAlgorithm: encAlgorithm, ops: ops)
    }
    
    /// Encoding logic
    public func encode(targetAlgorithm: CoseAlgorithm? = nil) throws -> [CBOR] {
        throw CoseError.unsupportedRecipient("\(type(of: self)) cannot be encoded.")
    }
    
    public func decrypt(targetAlgorithm: CoseAlgorithm) throws -> CoseKey {
        throw CoseError.unsupportedRecipient("\(type(of: self)) cannot decrypt a key.")
    }
    
    /// The peer's static key: from the message headers when present,
    /// otherwise from `localAttrs` (for example when the message only
    /// carries the key's ID).
    func peerStaticKey() -> EC2Key? {
        if let key = (try? getAttr(StaticKey())) as? EC2Key {
            return key
        }
        return localAttrs[StaticKey()] as? EC2Key
    }
    
    /// For static-static key agreement, adds the sender's public key to the
    /// unprotected header unless the message already identifies it.
    func includeStaticSenderKey() throws {
        guard (try? getAttr(StaticKey())) == nil, (try? getAttr(StaticKeyID())) == nil else {
            return
        }
        guard let sender = key as? EC2Key else {
            throw CoseError.invalidKey("Static sender key cannot be nil.")
        }
        let publicKey = try EC2Key(curve: sender.curve, x: sender.x, y: sender.y)
        uhdrUpdate([StaticKey(): publicKey])
    }
    
    // MARK: - Initialization
    /// Create a COSE Recipient message.
    /// - Parameters:
    ///   - phdr: Protected header.
    ///   - uhdr: Unprotected header.
    ///   - payload: The payload of the COSE message.
    ///   - externalAAD: The external additional authenticated data.
    ///   - key: The key for encryption/decryption.
    ///   - recipients: The list of `CoseRecipient` objects.
    public required init(phdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                         uhdr: OrderedDictionary<CoseHeaderAttribute, Any>? = nil,
                         payload: Data = Data(),
                         externalAAD: Data = Data(),
                         key: CoseKey? = nil,
                         recipients: [CoseRecipient] = []) {
        super.init(phdr: phdr, uhdr: uhdr, payload: payload, externalAAD: externalAAD, key: key)
        self.recipients = recipients
    }
    
    // MARK: - Methods
    public class func fromAlgorithm(algorithm: CoseAlgorithm) -> CoseRecipient.Type? {
        let algorithmIdentifier: CoseAlgorithmIdentifier
        if let fullname = algorithm.fullname {
            guard let id = CoseAlgorithmIdentifier.fromFullName(fullname) else { return nil }
            algorithmIdentifier = id
        } else if let identifier = algorithm.identifier {
            guard let id = CoseAlgorithmIdentifier(rawValue: identifier) else { return nil }
            algorithmIdentifier = id
        } else {
            return nil
        }
        
        switch algorithmIdentifier {
            case .direct, .directHKDFAES256, .directHKDFSHA256:
                return DirectEncryption.self
            case .ecdhES_HKDF_256, .ecdhES_HKDF_512, .ecdhSS_HKDF_256, .ecdhSS_HKDF_512:
                return DirectKeyAgreement.self
            case .ecdhES_A128KW, .ecdhES_A192KW, .ecdhES_A256KW, .ecdhSS_A128KW, .ecdhSS_A192KW, .ecdhSS_A256KW:
                return KeyAgreementWithKeyWrap.self
            case .aesKW_128, .aesKW_192, .aesKW_256, .rsa_ES_OAEP_SHA1, .rsa_ES_OAEP_SHA256, .rsa_ES_OAEP_SHA512:
                return KeyWrap.self
            default:
                return nil
        }
    }
    
    /// Create a recipient instance based on the COSE object
    public class func createRecipient<T>(recipient: [CBOR], context: String) throws -> T {
        guard recipient.count >= 3 else {
            throw CoseError.invalidMessage("Recipient structure must have at least 3 elements.")
        }
        
        // 1. Parse the Protected Header
        // Check if the first item in the recipient array is not empty
        let pAlg: CoseAlgorithm?
        let protectedHeader = recipient[0]
        var pHdr: OrderedDictionary<CoseHeaderAttribute, Any> = [:]
        
        if let pBytes = protectedHeader.byteStringValue, !pBytes.isEmpty {
            let decoded = try CBORSerialization.cborRejectingDuplicateKeys(from: pBytes)
            pHdr = try parseHeader(hdr: headerMap(from: decoded))
            
            if let alg = pHdr[Algorithm()] {
                pAlg = try CoseAlgorithm.fromId(for: alg)
            } else  {
                pAlg = nil
            }
        } else if protectedHeader.byteStringValue == nil {
            throw CoseError.invalidMessage("The protected header must be a byte string")
        } else {
            pAlg = nil
        }
        
        // 2. Parse the Unprotected Header
        // Parse the unprotected algorithm
        let uAlg: CoseAlgorithm?
        let unprotectedHeader = recipient[1]
        var unprotectedAttributes: OrderedDictionary<CoseHeaderAttribute, Any> = [:]
        
        unprotectedAttributes = try parseHeader(hdr: headerMap(from: unprotectedHeader))
        
        // Extract the algorithm from unprotected attributes
        if let alg = unprotectedAttributes[Algorithm()] {
            uAlg = try CoseAlgorithm.fromId(for: alg)
        } else {
            uAlg = nil
        }

        // Determine the appropriate recipient class based on the algorithms
        guard let algorithm = pAlg ?? uAlg else {
            throw CoseError.invalidMessage("No algorithm specified in recipient structure.")
        }
        guard let coseRecipientClass = fromAlgorithm(algorithm: algorithm) else {
            throw CoseError.unsupportedRecipient(
                "No recipient class for algorithm \(String(describing: algorithm.fullname))."
            )
        }
        guard let result = try coseRecipientClass.fromCoseObject(
            coseObj: recipient,
            context: context
        ) as? T else {
            throw CoseError.invalidMessage("Decoded recipient is not a \(T.self).")
        }
        return result
    }
    
    public static func verifyRecipients(_ recipients: [CoseRecipient]) throws -> Set<AnyHashable> {
        var recipientTypes: Set<AnyHashable> = []

        for recipient in recipients {
            recipientTypes.insert(String(describing: type(of: recipient)))
        }

        if recipientTypes.contains(String(describing: DirectEncryption.self)) && recipientTypes.count > 1 {
            throw CoseError.invalidRecipientConfiguration("When using DIRECT_ENCRYPTION mode, it must be the only mode used on the message.")
        }

        if recipientTypes.contains(String(describing: DirectKeyAgreement.self)) && recipients.count > 1 {
            throw CoseError.invalidRecipientConfiguration("When using DIRECT_KEY_AGREEMENT, it must be only one recipient in the message.")
        }

        return recipientTypes
    }
    
    /// Checks if a specific recipient is in the hierarchy of recipients.
    /// - Parameters:
    ///   - target: The `CoseRecipient` to search for.
    ///   - recipients: The list of `CoseRecipient` objects to search within.
    /// - Returns: A Boolean indicating whether the target recipient is found.
    public class func hasRecipient(target: CoseRecipient, in recipients: [CoseRecipient]) -> Bool {
        for recipient in recipients {
            if recipient === target { // Swift equivalent of Python's `is`
                return true
            } else if !recipient.recipients.isEmpty {
                if hasRecipient(target: target, in: recipient.recipients) {
                    return true
                }
            }
        }
        return false
    }
    
    /// Create a COSE KDF context for use by the key derivation algorithms.
    /// - Parameter algorithm: Specifies the target algorithm that will use the derived key.
    /// - Returns: A `CoseKDFContext` object.
    func getKDFContext(algorithm: CoseAlgorithm) throws -> CoseKDFContext {
        
        // Extract PartyU information (each field is optional)
        let uID = (try? getAttr(PartyUID())) as? Data
        let uNonce = (try? getAttr(PartyUNonce())) as? Data
        let uOther = (try? getAttr(PartyUOther())) as? Data
        let partyU = PartyInfo(identity: uID, nonce: uNonce, other: uOther)
        
        // Extract PartyV information (each field is optional)
        let vID = (try? getAttr(PartyVID())) as? Data
        let vNonce = (try? getAttr(PartyVNonce())) as? Data
        let vOther = (try? getAttr(PartyVOther())) as? Data
        let partyV = PartyInfo(identity: vID, nonce: vNonce, other: vOther)
        
        // Create the SuppPubInfo over the recipient's encoded protected header
        let keyLength = try contentKeyLength(for: algorithm)
        let suppPubOther = localAttrs[SuppPubOther()] as? Data ?? Data()
        let suppPub = try SuppPubInfo(
            keyDataLength: keyLength,
            protected: self.phdr,
            protectedEncoded: self.phdrEncoded,
            other: suppPubOther
        )
        
        // Get SuppPrivOther attribute
        let suppPriv = localAttrs[SuppPrivOther()] as? Data ?? Data()
        
        // Return the constructed KDF context
        return CoseKDFContext(
            algorithm: algorithm,
            suppPubInfo: suppPub,
            partyUInfo: partyU,
            partyVInfo: partyV,
            suppPrivInfo: suppPriv
        )
    }
    
    /// Sets up an ephemeral key and updates the unprotected header.
    /// - Parameters:
    ///   - peerKey: The peer's EC2 key.
    ///   - optionalParams: Optional parameters for key generation.
    /// - Throws: `CoseError` if an unrelated ephemeral key is already present.
    func setupEphemeralKey(peerKey: EC2Key, optionalParams: [AnyHashable: Any] = [:]) throws {
        
        // Check if the ephemeral key is already set in the headers
        if let _ = try? getAttr(EphemeralKey()) {
            throw CoseError.invalidMessage("Unrelated ephemeral public key found in COSE message header")
        }
        
        // Generate the ephemeral key using the curve from the peer key. The
        // recipient keeps the private key for the key agreement.
        let ephemeralKey = try EC2Key
            .generateKey(curve: peerKey.curve, optionalParams: optionalParams)
        self.key = ephemeralKey
        
        // Only the public part goes in the unprotected header.
        let publicKey = try EC2Key(
            curve: ephemeralKey.curve,
            x: ephemeralKey.x,
            y: ephemeralKey.y
        )
        uhdrUpdate([EphemeralKey(): publicKey])
    }
}

// MARK: - Content keys for any target algorithm

/// The length in bytes of the key a target algorithm uses.
func contentKeyLength(for algorithm: CoseAlgorithm) throws -> Int {
    switch algorithm {
        case let alg as EncAlgorithm:
            guard let keyLength = alg.keyLength else {
                throw CoseError.invalidAlgorithm("The target algorithm has no key length.")
            }
            return keyLength
        case let alg as AesMacAlgorithm:
            return alg.keyLength
        case let alg as HmacAlgorithm:
            // RFC 9053, section 3.1: the key is the size of the hash output.
            switch alg.hashFunction {
                case .sha1: return 20
                case .sha256: return 32
                case .sha384: return 48
                case .sha512: return 64
            }
        default:
            throw CoseError.invalidAlgorithm("No key length for \(String(describing: algorithm.fullname)).")
    }
}

/// The key operations a content key allows: encrypt/decrypt for content
/// encryption, MAC create/verify for MAC algorithms.
func contentKeyOps(for algorithm: CoseAlgorithm, ops: String) -> [KeyOps] {
    if algorithm is EncAlgorithm {
        return ops == "encrypt" ? [EncryptOp()] : [DecryptOp()]
    }
    return ops == "encrypt" ? [MacCreateOp()] : [MacVerifyOp()]
}
