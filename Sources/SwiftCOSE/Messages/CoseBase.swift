import Foundation
import PotentCBOR
import OrderedCollections

/// Basic COSE information buckets.
public class CoseBase {
    // MARK: - Properties
    public var payload: Data?
    public var algTstrEncoding: Bool = false

    /// The protected header, stored as a dictionary of attributes.
    private var _phdr: [CoseHeaderAttribute: Any] = [:]
    
    /// The encoded version of the protected header.
    private var _phdrEncoded: Data? = nil
    
    /// The unprotected header, stored as a dictionary of attributes.
    private var _uhdr: [CoseHeaderAttribute: Any] = [:]
    private var _localAttrs: [CoseHeaderAttribute: Any] = [:]
    
    // MARK: - Protected Header (phdr)
    public var phdr: [CoseHeaderAttribute: Any] {
        get {
            return _phdr
        }
        set {
            _phdr = newValue
            _phdrEncoded = nil // Reset encoded value
        }
    }
    
    // MARK: - Unprotected Header (uhdr)
    public var uhdr: [CoseHeaderAttribute: Any] {
        get {
            return _uhdr
        }
        set {
            _uhdr = newValue
        }
    }
    
    // MARK: - Local Attributes (localAttrs)
    public var localAttrs: [CoseHeaderAttribute: Any] {
        get {
            return _localAttrs
        }
        set {
            newValue.forEach { key, value in
                _localAttrs[key] = value
            }
        }
    }
    
    // MARK: - Encoded Protected Header (phdrEncoded)

    /// Encodes the protected header as CBOR.
    ///
    /// - Returns: The encoded protected header as `Data`.
    /// - Throws: An error if CBOR encoding fails.
    public var phdrEncoded: Data {
        get {
            if let encoded = _phdrEncoded {
                return encoded
            }
            
            guard !phdr.isEmpty else { return Data() }

            do {
                // Convert `_phdr` to a CBOR.Map by mapping its keys and values
                let protectedHdrMap = CBOR.map((_phdr as Dictionary<AnyHashable, Any>).mapKeysToCbor)
                
                let encoded = try CBORSerialization.data(from: protectedHdrMap)
                _phdrEncoded = encoded
                return encoded
            } catch {
                fatalError("Failed to encode protected header: \(error)")
            }
        }
    }

    // MARK: - Encoded Unprotected Header (uhdrEncoded)

    /// Encodes the unprotected header.
    ///
    /// - Returns: The encoded unprotected header as a dictionary.
    public var uhdrEncoded: [CoseHeaderAttribute: Any] {
        return _uhdr
    }

    // MARK: - Helper Methods

    /// Updates the protected header with new attributes.
    /// Resets the encoded version to ensure consistency.
    ///
    /// - Parameter params: The attributes to add to the protected header.
    public func updateProtectedHeader(with params: [CoseHeaderAttribute: Any]) {
        params.forEach { _phdr[$0.key] = $0.value }
        _phdrEncoded = nil // Reset encoded value to trigger re-encoding.
    }

    /// Updates the unprotected header with new attributes.
    ///
    /// - Parameter params: The attributes to add to the unprotected header.
    public func updateUnprotectedHeader(with params: [CoseHeaderAttribute: Any]) {
        params.forEach { _uhdr[$0.key] = $0.value }
    }

    // MARK: - Initialization

    /// Initializes a new instance of the CoseBase class.
    ///
    /// - Parameters:
    ///   - phdr: The initial protected header (optional).
    ///   - uhdr: The initial unprotected header (optional).
    public init(phdr: [CoseHeaderAttribute: Any]? = nil, uhdr: [CoseHeaderAttribute: Any]? = nil) {
        if let phdr = phdr {
            self._phdr = phdr
        }
        if let uhdr = uhdr {
            self._uhdr = uhdr
        }
    }
    
    // MARK: - Initialization
    public init(phdr: [CoseHeaderAttribute: Any]? = nil, uhdr: [CoseHeaderAttribute: Any]? = nil, payload: Data? = nil, phdrEncoded: Data? = nil, algTstrEncoding: Bool? = false) throws {
        if phdr != nil && phdrEncoded != nil {
            throw CoseError.valueError("Cannot have both phdr and phdrEncoded")
        }
        
        if phdrEncoded != nil {
            if phdrEncoded!.isEmpty {
                self.phdr = [:]
            } else {
                let decoded = try CBORSerialization.cbor(from: phdrEncoded!)
                self.phdr = try CoseBase.parseHeader(hdr: decoded.unwrapped as! [AnyHashable: Any])
                
                if let algId = self.phdr[Algorithm()] {
                    let coseAlg = try CoseAlgorithm.fromId(for: algId)
                    self.phdr[Algorithm()] = coseAlg
                }
            }
            
        } else if phdr == nil {
            self.phdr = [:]
        }

        self.uhdr = uhdr ?? [:] as! [CoseHeaderAttribute : Any]
        if let algId = self.uhdr[Algorithm()] {
            let coseAlg = try CoseAlgorithm.fromId(for: algId)
            self.uhdr[Algorithm()] = coseAlg
        }
        self.algTstrEncoding = algTstrEncoding ?? false
        
        self._phdrEncoded = phdrEncoded

        if let p = payload, !p.isEmpty {
            throw CoseError.valueError("Payload cannot be empty")
        }
        self.payload = payload
    }

    // MARK: - Methods
    public class func fromCoseObject(coseObj: [CBOR]) throws -> CoseBase {
        guard coseObj.count >= 2 else {
            throw CoseError.valueError("Insufficient elements in coseObj to construct a CoseBase")
        }
        
        var unprotectedAttributes: [CoseHeaderAttribute: Any] = [:]
        
        let phdrEncoded = coseObj[0]
        let uhdr = coseObj[1]
        if let uhdrMap = uhdr.unwrapped as? [AnyHashable: Any] {
            unprotectedAttributes = try parseHeader(hdr: uhdrMap)
        }

        return try CoseBase(
            uhdr: unprotectedAttributes,
            phdrEncoded: phdrEncoded.bytesStringValue
        )
    }
    
    /// Fetches a header attribute from the COSE header buckets.
    /// - Parameters:
    ///   - attribute: A header parameter to fetch from the buckets.
    ///   - defaultResult: A default return value in case the attribute was not found.
    /// - Returns: If found returns a header attribute else 'None' or the default value.
    /// - Throws: `CoseError` When the same attribute is found in both the protected and unprotected header.
    public func getAttr(_ attribute: CoseHeaderAttribute, defaultResult: Any? = nil) throws -> Any? {
        let pAttr = phdr[attribute]
        let uAttr = uhdr[attribute]

        if pAttr == nil && uAttr == nil {
            throw CoseError.invalidHeader("MALFORMED: Missing header attribute")
        }

        return pAttr ?? uAttr ?? defaultResult
    }

    /// Updates the protected header with new attributes.
    /// Resets the encoded version to ensure consistency.
    ///
    /// - Parameter params: The attributes to add to the protected header.
    public func phdrUpdate(_ params: [CoseHeaderAttribute: Any]) {
        params.forEach { _phdr[$0.key] = $0.value }
        _phdrEncoded = nil
    }

    /// Updates the unprotected header with new attributes.
    ///
    /// - Parameter params: The attributes to add to the unprotected header.
    public func uhdrUpdate(_ params: [CoseHeaderAttribute: Any]) {
        params.forEach { _uhdr[$0.key] = $0.value }
    }

    // MARK: - Helper Methods
    public class func parseHeader(hdr: [AnyHashable: Any]) throws -> [CoseHeaderAttribute: Any] {
        var decodedHdr: [CoseHeaderAttribute: Any] = [:]
        
        for (key, value) in hdr {
            guard let attr = try? CoseHeaderAttribute.fromId(for: key) else {
                throw CoseError.invalidHeader("Invalid header attribute")
            }
            
            if let valueParser = attr.valueParser {
                decodedHdr[attr] = try valueParser(value)
            } else {
                decodedHdr[attr] = value
            }
        }
        
        return decodedHdr
    }
    
    public func hdrRepr() -> (phdr: [AnyHashable: Any], uhdr: [AnyHashable: Any]) {
        var phdr: [String: Any] = _phdr.reduce(into: [:]) { result, element in
            let keyName: String = element.key.fullname            
            result[keyName] = "\(type(of: element.value))"
        }

        var uhdr: [String: Any] = _uhdr.reduce(into: [:]) { result, element in
            let keyName: String = element.key.fullname
            result[keyName] = "\(type(of: element.value))"
        }

        if let iv = phdr["IV"] as? String, !iv.isEmpty {
            phdr["IV"] = truncate(iv)
        }

        if let iv = uhdr["IV"] as? String, !iv.isEmpty {
            uhdr["IV"] = truncate(iv)
        }

        if let partialIv = phdr["PARTIAL_IV"] as? String, !partialIv.isEmpty {
            phdr["PARTIAL_IV"] = truncate(partialIv)
        }

        if let partialIv = uhdr["PARTIAL_IV"] as? String, !partialIv.isEmpty {
            uhdr["PARTIAL_IV"] = truncate(partialIv)
        }

        return (phdr, uhdr)
    }
}