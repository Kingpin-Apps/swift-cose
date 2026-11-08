import Foundation
import CBORCodable
import OrderedCollections

// MARK: - PotentCBOR compatibility shim
//
// Bridges the small piece of PotentCBOR's API surface that swift-cose
// relied on but that CBORCodable intentionally doesn't expose in the
// same shape. Pure adapters — no behavioral change.

/// Drop-in replacement for `PotentCBOR.CBORSerialization`. PotentCBOR
/// exposed read/write of a top-level CBOR item as `cbor(from:)` and
/// `data(from:)`; CBORCodable does the same via its writer/reader types
/// directly. Keeping the old surface lets the migration touch every
/// other call site without breaking encapsulation here.
public enum CBORSerialization {

    /// Decode the bytes as a single CBOR data item. Mirrors PotentCBOR's
    /// lenient behavior: trailing bytes after the first complete item
    /// are ignored (some swift-cose call sites pass concatenated CBOR
    /// streams and only want the first item back). Use `CBORReader`
    /// directly if you need strict single-item enforcement.
    public static func cbor(from data: Data) throws -> CBOR {
        var reader = CBORReader(data)
        return try reader.decode()
    }

    /// Encode a CBOR value to bytes.
    public static func data(from cbor: CBOR) throws -> Data {
        var writer = CBORWriter()
        try writer.encode(cbor)
        return writer.data
    }

    /// Decode one CBOR data item that must fill `data`, throwing on a map
    /// with a repeated key. RFC 9052, section 3 forbids duplicate labels,
    /// and the plain reader would silently keep only the last one.
    static func cborRejectingDuplicateKeys(from data: Data) throws -> CBOR {
        var reader = CBORReader(data)
        let value = try decodeRejectingDuplicateKeys(&reader, depth: 0)
        guard reader.isAtEnd else {
            throw CoseError.invalidMessage("Unexpected bytes after the CBOR item")
        }
        return value
    }

    private static func decodeRejectingDuplicateKeys(_ reader: inout CBORReader, depth: Int) throws -> CBOR {
        guard depth < CBORReader.defaultMaxDepth else {
            throw CoseError.invalidMessage("CBOR nesting is too deep")
        }
        var probe = reader
        let head = try probe.readHead()
        if head.isIndefinite {
            return try reader.decode()
        }
        switch head.majorType {
            case .array, .map:
                // Each item takes at least one byte, so a count larger than
                // what is left is malformed; checking first avoids looping.
                guard let count = Int(exactly: head.argument), count <= probe.remaining else {
                    throw CoseError.invalidMessage("CBOR length exceeds the input")
                }
                reader = probe
                if head.majorType == .array {
                    var items: [CBOR] = []
                    for _ in 0..<count {
                        items.append(try decodeRejectingDuplicateKeys(&reader, depth: depth + 1))
                    }
                    return .array(items)
                }
                var map = OrderedDictionary<CBOR, CBOR>()
                for _ in 0..<count {
                    let key = try decodeRejectingDuplicateKeys(&reader, depth: depth + 1)
                    guard map[key] == nil else {
                        throw CoseError.invalidMessage("Duplicate key in CBOR map")
                    }
                    map[key] = try decodeRejectingDuplicateKeys(&reader, depth: depth + 1)
                }
                return .map(map)
            case .byteString, .textString:
                // A definite string can't be longer than what is left. Checking
                // here keeps a length near Int.max away from the reader.
                guard head.argument <= UInt64(probe.remaining) else {
                    throw CoseError.invalidMessage("CBOR length exceeds the input")
                }
                return try reader.decode()
            case .tagged:
                reader = probe
                return .tagged(head.argument, try decodeRejectingDuplicateKeys(&reader, depth: depth + 1))
            default:
                return try reader.decode()
        }
    }
}
