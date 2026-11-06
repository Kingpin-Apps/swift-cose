# ``SwiftCOSE``

A Swift implementation of CBOR Object Signing and Encryption (COSE).

## Overview

CBOR Object Signing and Encryption (COSE) is a data format for small, concise messages, designed for low-power devices. It is defined in [RFC 8152](https://www.rfc-editor.org/rfc/rfc8152), which has since been replaced by [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053). COSE messages can be encrypted, authenticated (MAC'ed), and signed.

Every COSE message has the same basic structure: a CBOR array that starts with three fields.

- **Protected header**: information that is covered by the encryption, MAC, or signature.
- **Unprotected header**: information that is not covered by the cryptographic algorithms.
- **Payload**: the message content, which is protected by the cryptographic algorithms.

Depending on the message type, the array then ends with:

- a single *MAC* or *signature* field for **MAC0** and **Sign1** messages, or
- a list of *COSE recipients* or *COSE signatures* for **MAC**, **Encrypt**, and **Sign** messages.

### Message types

SwiftCOSE supports all six COSE message types. Each one encodes as RFC 9052 describes and round-trips through ``CoseMessage/decode(_:from:)``; the test suite checks them against the published COSE Working Group examples.

- **Encrypt0** (``Enc0Message``): an encrypted message for a single recipient. The payload and external data are protected by a shared Content Encryption Key (CEK).
- **Encrypt** (``EncMessage``): an encrypted message that can have several recipients. Each recipient gets the CEK in one of these ways: directly (``DirectEncryption``), with AES key wrap or RSA-OAEP (``KeyWrap``), by ECDH key agreement with an ephemeral or a static sender key (``DirectKeyAgreement``), or by ECDH key agreement plus AES key wrap (``KeyAgreementWithKeyWrap``).
- **MAC0** (``Mac0Message``): an authenticated message for a single recipient.
- **MAC** (``MacMessage``): an authenticated message that can have several recipients. Recipients get the MAC key the same ways as for Encrypt: directly, with AES key wrap, or by ECDH key agreement with or without AES key wrap. Use ``MacMessage/verifyTag(recipient:)`` to check a received message with one recipient's key.
- **Sign1** (``Sign1Message``): a signed message with a single signature. The payload can be detached: it is then sent as `nil` and passed to the encode and verify calls instead.
- **Sign** (``SignMessage``): a message signed by one or more signers. Each signature is carried in its own COSE signature structure (``CoseSignature``).

Use ``CoseMessage/decode(_:from:)`` to decode CBOR-encoded bytes. The CBOR tag selects the message type: pass `CoseMessage.self` to accept any type, or a specific class such as `Sign1Message.self` to accept only that type.

### Keys

COSE Key objects store and transport cryptographic keys. SwiftCOSE supports these key types:

- **EC2** (``EC2Key``): elliptic curve keys with an x/y-coordinate pair.
- **OKP** (``OKPKey``): octet key pairs, such as Ed25519 and X25519 keys.
- **RSA** (``RSAKey``): RSA keys.
- **Symmetric** (``CoseSymmetricKey``): keys for symmetric cryptography.

## Topics

### Messages

- ``CoseMessage``
- ``Sign1Message``
- ``SignMessage``
- ``CoseSignature``
- ``Mac0Message``
- ``MacMessage``
- ``Enc0Message``
- ``EncMessage``

### Recipients

- ``CoseRecipient``
- ``DirectEncryption``
- ``DirectKeyAgreement``
- ``KeyWrap``
- ``KeyAgreementWithKeyWrap``
- ``CoseKDFContext``

### Headers

- ``CoseHeaderAttribute``
- ``Algorithm``
- ``KID``
- ``IV``
- ``PartialIV``
- ``ContentType``
- ``Critical``

### Keys

- ``CoseKey``
- ``EC2Key``
- ``OKPKey``
- ``RSAKey``
- ``CoseSymmetricKey``
- ``CoseCurve``
- ``KeyOps``

### Algorithms

- ``CoseAlgorithm``
- ``CoseAlgorithmIdentifier``
- ``EcdsaAlgorithm``
- ``EdDSAAlgorithm``
- ``RsaAlgorithm``
- ``HmacAlgorithm``
- ``AesMacAlgorithm``
- ``AesGcmAlgorithm``
- ``AesCcmAlgorithm``
- ``AesKwAlgorithm``
- ``EcdhHkdfAlgorithm``
