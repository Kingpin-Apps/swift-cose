## 1.3.0 (2026-05-31)

### Refactor

- drop direct OpenSSL-Package dependency: SHAKE-128/256 now use shared swift-goldilocks on all platforms (was: Apple/Linux on OpenSSL EVP, Android/Wasm on Goldilocks); RSA keygen now uses CryptoSwift's `RSA(keySize:)` (was: OpenSSL `BN_generate_prime_ex`)
- delete `CCOSEOpenSSL` system-library target and the Linux `libssl-dev`/`openssl-devel` runtime requirement
- RSA keygen now runs on Android/Wasi (previously threw); probable primes match FIPS 186-5 / BoringSSL / swift-crypto `_RSA` (was: safe primes via OpenSSL — slower for no security benefit at modern key sizes)
- RSA keygen measured **3.1×–12× faster** on M1 Max (1.92s vs 6.27s at 2048-bit; 17.7s vs 210s at 4096-bit)
- bump swift-curve448 to 0.3.0, which itself dropped OpenSSL-Package — downstream Mach-Os no longer load `@rpath/OpenSSL.framework` transitively

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
