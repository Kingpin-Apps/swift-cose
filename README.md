![GitHub Workflow Status](https://github.com/Kingpin-Apps/swift-cose/actions/workflows/swift.yml/badge.svg)

# SwiftCOSE - CBOR Object Signing and Encryption

This project is a Swift implementation of the IETF CBOR Encoded Message Syntax (COSE). COSE has reached RFC status and is now available at RFC 8152.

## Platform support

| Platform | Status |
|---|---|
| iOS / macOS / watchOS / tvOS / visionOS | ✓ |
| Linux | ✓ |
| Android | ✓ |
| WebAssembly (WASI) | ✗ — blocked upstream |

WASM is blocked by `apple/swift-crypto`'s `_CryptoExtras` module (pulled in transitively via `swift-certificates`/`X509`): `Sources/_CryptoExtras/Util/ThreadSpecific/ThreadSpecific.swift` references a `ThreadOpsSystem` typealias that has no WASI implementation. Upstream itself is not green for WASM — see the [swift-crypto build matrix](https://swiftpackageindex.com/apple/swift-crypto/builds). We'll revisit when upstream lands WASI support.

## Usage
To add SwiftCOSE as dependency to your Xcode project, select `File` > `Swift Packages` > `Add Package Dependency`, enter its repository URL: `https://github.com/Kingpin-Apps/swift-cose.git` and import `SwiftCOSE`.

    ```swift
    dependencies: [
        .package(url: "https://github.com/Kingpin-Apps/swift-cose.git", from: "0.0.1")
    ]
    ```

Then, to use it in your source code, add:

```swift
import SwiftCOSE
```

## What is COSE ?
CBOR Encoded Message Syntax (COSE) is a data format for concise representation of small messages [RFC 8152](https://tools.ietf.org/html/rfc8152). COSE is optimized for low power devices. The messages can be encrypted, MAC'ed and signed. There are 6 different types of COSE messages:

- **Encrypt0**: An encrypted COSE message with a single recipient. The payload and AAD are protected by a shared CEK (Content Encryption Keys)
- **Encrypt**: An encrypted COSE message can have multiple recipients. For each recipient the CEK is encrypted with a KEK (Key Encryption Key) - using AES key wrap - and added to the message.
- **MAC0**: An authenticated COSE message with one recipient.
- **MAC**: An authenticated COSE message that can have multiple recipients. For each recipient, the authentication key is encrypted with a KEK and added to the message.
- **Sign1**: A signed COSE message with a single signature.
- **Sign**: A COSE message that has been signed by multiple entities (each signature is carried in a COSE signature structure, added to the message).

A basic COSE message consists of 2 _information_ _buckets_ and the _payload_:

- **Protected header**: This message field contains information that needs to be protected. This information is taken into account during the encryption, calculation of the MAC or the signature.
- **Unprotected header**: The information contained in the unprotected header is not protected by the cryptographic algorithms.
- **Payload**: Contains the payload of the message, protected (mac'ed, signed or encrypted) by the cryptographic algorithms.

Additionally, based on the message type, other message fields can be added:

- _MAC_ or _signature_ (for **MAC0** or **Sign1** messages)
- _COSE recipients_ or _COSE signatures_ (for **MAC**, **Encrypt**, and **Sign** messages)

## Examples

### Encoding
```swift
import SwiftCOSE

// Create a COSE Encrypt0 Message
let msg = Enc0Message(
    phdr: [
        Algorithm(): A128GCM(),
        IV(): Data([0x01, 0x02, 0x03, 0x04])
    ],
    uhdr: [
        KID(): Data("test.guy@example.com".utf8)
    ],
    payload: Data("A secret message".utf8)
)

// Create a COSE Symmetric Key
let coseKey = SymmetricKey.generateKey(keyLength: 32)
msg.key = coseKey

// Performs encryption and CBOR serialization
msg.encode()
```

### Decoding
```swift
import SwiftCOSE

// message bytes (CBOR encoded)
let msg = Data([0xd8, 0x3d, 0x85, 0x01, 0x01, 0xa0, 0x01, 0x02, 0x03, 0x04, 0x58, 0x14, 0x54, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65])

let coseMsg = Enc0Message.decode(from: msg)

// Create a COSE Symmetric Key
let coseKey = SymmetricKey.generateKey(keyLength: 32)
msg.key = coseKey

msg.decrypt()
```

