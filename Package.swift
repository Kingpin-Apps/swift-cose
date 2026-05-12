// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftCOSE",
    platforms: [
      .iOS(.v16),
      .macOS(.v13),
      .watchOS(.v9),
      .tvOS(.v16),
      .visionOS(.v1)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftCOSE",
            targets: ["SwiftCOSE"]),
    ],
    dependencies: [
        .package(url: "https://github.com/KINGH242/PotentCodables.git", .upToNextMinor(from: "3.6.0")),
        .package(url: "https://github.com/leif-ibsen/Digest.git", from: "1.11.0"),
        .package(url: "https://github.com/tesseract-one/UncommonCrypto.swift.git",
                 .upToNextMinor(from: "0.2.1")),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.6.1"),
        // Prebuilt OpenSSL xcframework for Apple platforms only; Linux uses system libcrypto via COpenSSL target.
        .package(url: "https://github.com/krzyzanowskim/OpenSSL-Package.git", .upToNextMinor(from: "3.3.2000")),
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", from: "0.22.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.9.0")),
        .package(url: "https://github.com/Kingpin-Apps/swift-curve448.git", from: "0.1.4"),
        // Provides Crypto-compatible APIs (SHA, HMAC, Curve25519, P256/P384/P521, AES.GCM, HKDF…)
        // on Linux, where CryptoKit is unavailable.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.15.1"),
    ],
    targets: [
        // System libcrypto on Linux — provides the same `BN_*` symbols that
        // `OpenSSL-Package` ships prebuilt on Apple. Sources import either
        // `OpenSSL` or `CCOSEOpenSSL` via `#if canImport(...)`. The unusual
        // module name avoids collisions with similarly-named system-library
        // targets in sibling packages (e.g. `swift-curve448` ships `COpenSSL`).
        .systemLibrary(
            name: "CCOSEOpenSSL",
            pkgConfig: "libcrypto",
            providers: [
                .apt(["libssl-dev"]),
                .yum(["openssl-devel"]),
            ]
        ),
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftCOSE",
            dependencies: [
                "PotentCodables",
                .product(name: "Digest", package: "digest"),
                .product(name: "UncommonCrypto", package: "UncommonCrypto.swift"),
                .product(name: "X509", package: "swift-certificates"),
                .product(
                    name: "OpenSSL",
                    package: "OpenSSL-Package",
                    condition: .when(platforms: [.iOS, .macOS, .watchOS, .tvOS, .visionOS, .macCatalyst])
                ),
                .target(
                    name: "CCOSEOpenSSL",
                    condition: .when(platforms: [.linux, .android])
                ),
                .product(name: "P256K", package: "swift-secp256k1"),
                .product(name: "SwiftCurve448", package: "swift-curve448"),
                // Only link swift-crypto on Linux; on Apple platforms CryptoKit ships with the OS.
                .product(
                    name: "Crypto",
                    package: "swift-crypto",
                    condition: .when(platforms: [.linux])
                ),
                "CryptoSwift",

            ]
        ),
        .testTarget(
            name: "SwiftCOSETests",
            dependencies: ["SwiftCOSE"],
            resources: [
               .copy("data")
           ]
        ),
    ]
)
