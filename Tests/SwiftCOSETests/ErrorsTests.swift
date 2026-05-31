import Testing
@testable import SwiftCOSE

struct CoseErrorTests {
    
    @Test func testCoseErrorAttributeError() async throws {
        let error = CoseError.attributeError("Missing attribute")
        #expect(validateErrorCase(error, expected: "Missing attribute"))
    }
    
    @Test func testCoseErrorGenericError() async throws {
        let error = CoseError.genericError("Unknown error")
        #expect(validateErrorCase(error, expected: "Unknown error"))
    }
    
    @Test func testCoseErrorInvalidCurve() async throws {
        let error = CoseError.invalidCurve("Unsupported curve P-521")
        #expect(validateErrorCase(error, expected: "Unsupported curve P-521"))
    }
    
    @Test func testCoseErrorInvalidKeyOps() async throws {
        let error = CoseError.invalidKeyOps("Invalid key operation")
        #expect(validateErrorCase(error, expected: "Invalid key operation"))
    }
    
    @Test func testCoseErrorInvalidKeyType() async throws {
        let error = CoseError.invalidKeyType("Unsupported key type")
        #expect(validateErrorCase(error, expected: "Unsupported key type"))
    }
    
    @Test func testCoseErrorInvalidAlgorithm() async throws {
        let error = CoseError.invalidAlgorithm("Algorithm not recognized")
        #expect(validateErrorCase(error, expected: "Algorithm not recognized"))
    }
    
    @Test func testCoseErrorInvalidCertificate() async throws {
        let error = CoseError.invalidCertificate("Certificate malformed")
        #expect(validateErrorCase(error, expected: "Certificate malformed"))
    }
    
    @Test func testCoseErrorInvalidKey() async throws {
        let error = CoseError.invalidKey("Invalid key data")
        #expect(validateErrorCase(error, expected: "Invalid key data"))
    }
    
    @Test func testCoseErrorInvalidKeyFormat() async throws {
        let error = CoseError.invalidKeyFormat("Incorrect key format")
        #expect(validateErrorCase(error, expected: "Incorrect key format"))
    }
    
    @Test func testCoseErrorInvalidKIDValue() async throws {
        let error = CoseError.invalidKIDValue("KID value error")
        #expect(validateErrorCase(error, expected: "KID value error"))
    }
    
    @Test func testCoseErrorInvalidIV() async throws {
        let error = CoseError.invalidIV("IV value invalid")
        #expect(validateErrorCase(error, expected: "IV value invalid"))
    }
    
    @Test func testCoseErrorInvalidCriticalValue() async throws {
        let error = CoseError.invalidCriticalValue("Critical value missing")
        #expect(validateErrorCase(error, expected: "Critical value missing"))
    }
    
    @Test func testCoseErrorInvalidContentType() async throws {
        let error = CoseError.invalidContentType("Unsupported content type")
        #expect(validateErrorCase(error, expected: "Unsupported content type"))
    }
    
    @Test func testCoseErrorInvalidHeader() async throws {
        let error = CoseError.invalidHeader("Header malformed")
        #expect(validateErrorCase(error, expected: "Header malformed"))
    }
    
    @Test func testCoseErrorInvalidMessage() async throws {
        let error = CoseError.invalidMessage("Message corrupted")
        #expect(validateErrorCase(error, expected: "Message corrupted"))
    }
    
    @Test func testCoseErrorInvalidRecipientConfiguration() async throws {
        let error = CoseError.invalidRecipientConfiguration("Recipient misconfigured")
        #expect(validateErrorCase(error, expected: "Recipient misconfigured"))
    }
    
    @Test func testCoseErrorMalformedMessage() async throws {
        let error = CoseError.malformedMessage("Malformed COSE message")
        #expect(validateErrorCase(error, expected: "Malformed COSE message"))
    }
    
    @Test func testCoseErrorNotImplemented() async throws {
        let error = CoseError.notImplemented("Feature not available")
        #expect(validateErrorCase(error, expected: "Feature not available"))
    }
    
    @Test func testCoseErrorUnknownAttribute() async throws {
        let error = CoseError.unknownAttribute("Unknown attribute encountered")
        #expect(validateErrorCase(error, expected: "Unknown attribute encountered"))
    }
    
    @Test func testCoseErrorUnsupportedCurve() async throws {
        let error = CoseError.unsupportedCurve("Curve not supported")
        #expect(validateErrorCase(error, expected: "Curve not supported"))
    }
    
    @Test func testCoseErrorUnsupportedRecipient() async throws {
        let error = CoseError.unsupportedRecipient("Recipient type unsupported")
        #expect(validateErrorCase(error, expected: "Recipient type unsupported"))
    }
    
    @Test func testCoseErrorValueError() async throws {
        let error = CoseError.valueError("Incorrect value")
        #expect(validateErrorCase(error, expected: "Incorrect value"))
    }
    
    /// Helper function to validate error cases
    private func validateErrorCase(_ error: CoseError, expected: String) -> Bool {
        switch error {
        case .attributeError(let message),
             .genericError(let message),
             .invalidAttribute(let message),
             .invalidCurve(let message),
             .invalidKeyOps(let message),
             .invalidKeyType(let message),
             .invalidAlgorithm(let message),
             .invalidCertificate(let message),
             .invalidKey(let message),
             .invalidKeyFormat(let message),
             .invalidKIDValue(let message),
             .invalidIV(let message),
             .invalidCriticalValue(let message),
             .invalidContentType(let message),
             .invalidHeader(let message),
             .invalidMessage(let message),
             .invalidRecipientConfiguration(let message),
             .malformedMessage(let message),
             .notImplemented(let message),
             .unknownAttribute(let message),
             .unsupportedCurve(let message),
             .unsupportedRecipient(let message),
             .valueError(let message):
            return message == expected
        }
    }
}
