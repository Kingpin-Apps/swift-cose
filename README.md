![GitHub Workflow Status](https://github.com/Kingpin-Apps/swift-cose/actions/workflows/swift.yml/badge.svg)

# SwiftCOSE - CBOR Object Signing and Encryption

This project is a Swift implementation of the IETF CBOR Object Signing and Encryption (COSE) format. COSE was published as RFC 8152, which has since been replaced by RFC 9052 and RFC 9053.

## Platform support

| Platform | Status |
|---|---|
| iOS / macOS / watchOS / tvOS / visionOS | ✓ |
| Linux | ✓ |
| Android | ✓ |
| WebAssembly (WASI) | ✗ — blocked upstream |

WASM is blocked by `apple/swift-crypto`'s `_CryptoExtras` module (pulled in transitively via `swift-certificates`/`X509`): `Sources/_CryptoExtras/Util/ThreadSpecific/ThreadSpecific.swift` references a `ThreadOpsSystem` typealias that has no WASI implementation. Upstream itself is not green for WASM — see the [swift-crypto build matrix](https://swiftpackageindex.com/apple/swift-crypto/builds). We'll revisit when upstream lands WASI support.

## Usage
To add SwiftCOSE as a dependency to your Xcode project, select `File` > `Add Package Dependencies…`, enter its repository URL, `https://github.com/Kingpin-Apps/swift-cose.git`, and add `SwiftCOSE` to your target.

In a `Package.swift` file, add:

```swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-cose.git", from: "1.3.3")
]
```

Then, to use it in your source code, add:

```swift
import SwiftCOSE
```

## What is COSE ?
CBOR Object Signing and Encryption (COSE) is a data format for concise representation of small messages [RFC 8152](https://tools.ietf.org/html/rfc8152). COSE is optimized for low power devices. The messages can be encrypted, MAC'ed and signed. There are 6 different types of COSE messages:

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

Header buckets are `OrderedDictionary` values from [swift-collections](https://github.com/apple/swift-collections), so import `OrderedCollections` as well.

### Signing (COSE_Sign1)
```swift
import Foundation
import OrderedCollections
import SwiftCOSE

// Create an Ed25519 COSE key
let curve = try CoseCurve.fromId(for: CoseCurveIdentifier.ed25519)
let key = try OKPKey.generateKey(curve: curve)

let phdr: OrderedDictionary<CoseHeaderAttribute, Any> = [
    Algorithm(): EdDSAAlgorithm(),
    KID(): Data("test.guy@example.com".utf8)
]

let msg = Sign1Message(
    phdr: phdr,
    payload: Data("A signed message".utf8),
    key: key
)

// Signs the payload and serializes the message to CBOR
let encoded = try msg.encode()
```

### Verifying
```swift
// Decode the CBOR-encoded message
let decoded = try CoseMessage.decode(Sign1Message.self, from: encoded)

// Attach the signer's public key and check the signature
decoded.key = try OKPKey(curve: curve, x: key.x)
let isValid = try decoded.verifySignature()
```

### Encryption (COSE_Encrypt0)
```swift
// A 128-bit symmetric key shared by sender and receiver
let aesKey = try CoseSymmetricKey.generateKey(keyLength: 16)

let encMsg = Enc0Message(
    phdr: [Algorithm(): A128GCM()],
    // AES-GCM needs a fresh 12-byte nonce for every message
    uhdr: [IV(): Data((0..<12).map { _ in UInt8.random(in: 0...255) })],
    payload: Data("A secret message".utf8),
    key: aesKey
)

// Encrypts the payload and serializes the message to CBOR
let encrypted = try encMsg.encode()

// The receiver decodes the message and decrypts it with the same key
let received = try CoseMessage.decode(Enc0Message.self, from: encrypted)
received.key = aesKey
let plaintext = try received.decrypt()
```

### MAC (COSE_Mac0)
```swift
let macKey = try CoseSymmetricKey.generateKey(keyLength: 32)

let macMsg = Mac0Message(
    phdr: [Algorithm(): Hmac256()],
    payload: Data("An authenticated message".utf8),
    key: macKey
)

// Computes the authentication tag and serializes the message to CBOR
let maced = try macMsg.encode()

// The receiver decodes the message and checks the tag with the same key
let receivedMac = try CoseMessage.decode(Mac0Message.self, from: maced)
receivedMac.key = macKey
let isAuthentic = try receivedMac.verifyTag()
```

