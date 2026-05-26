import Foundation
import CBORCodable

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
}
