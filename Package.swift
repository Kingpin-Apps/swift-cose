// swift-tools-version: 6.1
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
        .library(
            name: "SwiftCOSE",
            targets: ["SwiftCOSE"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.6.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.7.0"),
        .package(url: "https://github.com/Kingpin-Apps/swift-curve448.git", from: "0.2.3"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cbor-codable.git", from: "0.3.1"),
        .package(url: "https://github.com/krzyzanowskim/OpenSSL-Package.git", .upToNextMinor(from: "3.3.2000")),
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", from: "0.22.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.9.0")),
        .package(url: "https://github.com/Kingpin-Apps/swift-goldilocks.git", from: "0.1.0"),
    ],
    targets: [
        .systemLibrary(
            name: "CCOSEOpenSSL",
            pkgConfig: "libcrypto",
            providers: [
                .apt(["libssl-dev"]),
                .yum(["openssl-devel"]),
            ]
        ),
        .target(
            name: "SwiftCOSE",
            dependencies: [
                .product(name: "CBORCodable", package: "swift-cbor-codable"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "X509", package: "swift-certificates"),
                .product(
                    name: "OpenSSL",
                    package: "OpenSSL-Package",
                    condition: .when(platforms: [.iOS, .macOS, .watchOS, .tvOS, .visionOS, .macCatalyst])
                ),
                .target(
                    name: "CCOSEOpenSSL",
                    condition: .when(platforms: [.linux])
                ),
                // SHAKE128/256 via libgoldilocks on Android + Wasm (no usable
                // libcrypto). Self-contained — has its own Keccak/SHAKE impl.
                .product(
                    name: "Goldilocks",
                    package: "swift-goldilocks",
                    condition: .when(platforms: [.android, .wasi])
                ),
                .product(name: "P256K", package: "swift-secp256k1"),
                .product(name: "SwiftCurve448", package: "swift-curve448"),
                // Link swift-crypto on non-Apple platforms; CryptoKit ships with the OS on Apple.
                .product(
                    name: "Crypto",
                    package: "swift-crypto",
                    condition: .when(platforms: [.linux, .android])
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
