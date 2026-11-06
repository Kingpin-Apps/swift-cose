## 2.0.0 (2026-11-06)

### Feat

- support key wrap and ECDH recipients in COSE_Mac

### Fix

- make ECDH static-static recipients send and find the sender key
- accept HMAC key sizes and throw on bad symmetric key lengths
- compute AES-CBC-MAC tags as RFC 9053 defines them
- run recipient checks when fromCoseObject is called without a context
- always emit a complete Mac0, Mac and Sign1 when not recomputing the tag
- throw instead of trapping on malformed headers, keys and CBOR
- make ECDH recipients agree on keys and read ephemeral keys
- throw instead of crashing on unsupported COSE_Mac recipients
- encode the COSE_KDF_Context as RFC 9053 defines it
- make AES key wrap recipients wrap and unwrap the CEK
- derive the nonce from the Partial IV and Base IV
- send a detached Sign1 payload as nil
- always sign both protected headers in the COSE_Sign Sig_structure
- decode every COSE message type and keep the received protected header
- encrypt AES-GCM without block padding
- include the payload in the MAC_structure
- throw from Data.toCBOR instead of crashing on non-CBOR bytes
- wrap protected headers and payloads in byte strings when encoding

## 1.3.3 (2026-10-07)

### Fix

- **deps**: accept CryptoSwift 1.10 and later 1.x

## 1.3.2 (2026-10-07)

### Fix

- **deps**: accept BigInt 6 as well as 5

## 1.3.1 (2026-06-07)

### Fix

- improve cross platform capability

## 1.3.0 (2026-05-31)

### Refactor

- drop OpenSSL-Package, use swift-goldilocks and CryptoSwift; bump swift-curve448 to 0.3.0

## 1.2.0 (2026-05-29)

### Fix

- update dependencies

## 1.1.0 (2026-05-28)

### Feat

- SHAKE via shared swift-goldilocks on Android/Wasm

## 1.0.1 (2026-05-28)

### Feat

- bump swift-curve448 to 0.2.1 for vendored Ed448/X448 on Android+Wasm

## 1.0.0 (2026-05-28)

### Feat

- drop Digest+UncommonCrypto, native CryptoKit/Crypto+OpenSSL EVP for SHAKE; fix SHA-384/512 to IANA spec

## 0.2.1 (2026-05-26)

### Fix

- use correct package swift-cbor-codable

## 0.2.0 (2026-05-26)

### Refactor

- migrate from PotentCBOR to CBORCodable

## 0.1.18 (2026-05-11)

### Fix

- improve platform compatibility

## 0.1.17 (2026-05-09)

### Fix

- add back try

## 0.1.16 (2026-05-09)

### Fix

- use swift-secp256k1 and fix warnings in tests

## 0.1.15 (2025-11-29)

### Fix

- set compatible versions and update swift-curve448 version

## 0.1.14 (2025-08-24)

### Fix

- update CryptoSwift and swift-curve448

## 0.1.13 (2025-08-24)

### Fix

- update to fork of potent codables

## 0.1.12 (2025-08-20)

### Fix

- update swift-curve448
- fix specialize static method error

## 0.1.11 (2025-03-12)

### Fix

- handle other types

## 0.1.10 (2025-03-12)

### Fix

- handle other dictionaries

## 0.1.9 (2025-03-12)

### Fix

- encode phdr to bytestring

## 0.1.8 (2025-03-11)

### Fix

- add EdDSAAlgorithm

## 0.1.7 (2025-03-11)

### Fix

- use OrderedDictionary and other fixes

## 0.1.6 (2025-03-08)

### Fix

- add hanlder for EdDSAAlgorithm and rename

## 0.1.5 (2025-03-08)

### Fix

- handle decoding and searching store

## 0.1.4 (2025-03-08)

### Fix

- handle custom headers in decoding

## 0.1.3 (2025-03-08)

### Fix

- handle CBOR tag decoding

## 0.1.2 (2025-03-07)

### Fix

- open classes

## 0.1.1 (2025-03-07)

### Fix

- make public
- all functions complete
- add more code
- add more and fix more
