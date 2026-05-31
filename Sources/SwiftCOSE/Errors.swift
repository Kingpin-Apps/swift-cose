import Foundation

/// `CoseError` is an enumeration of errors that can be thrown by the COSE library.
enum CoseError: Error {
    case attributeError(String)
    case genericError(String)
    case invalidAttribute(String)
    case invalidCurve(String)
    case invalidKeyOps(String)
    case invalidKeyType(String)
    case invalidAlgorithm(String)
    case invalidCertificate(String)
    case invalidKey(String)
    case invalidKeyFormat(String)
    case invalidKIDValue(String)
    case invalidIV(String)
    case invalidCriticalValue(String)
    case invalidContentType(String)
    case invalidHeader(String)
    case invalidMessage(String)
    case invalidRecipientConfiguration(String)
    case malformedMessage(String)
    case notImplemented(String)
    case unknownAttribute(String)
    case unsupportedCurve(String)
    case unsupportedRecipient(String)
    case valueError(String)
}
