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
        .package(url: "https://github.com/krzyzanowskim/OpenSSL-Package.git", .upToNextMinor(from: "3.3.2000")),
        .package(url: "https://github.com/Sajjon/K1.git", from: "0.3.9"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.9.0")),
        .package(url: "https://github.com/Kingpin-Apps/swift-curve448.git", from: "0.1.3")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftCOSE",
            dependencies: [
                "PotentCodables",
                .product(name: "Digest", package: "digest"),
                .product(name: "UncommonCrypto", package: "UncommonCrypto.swift"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "OpenSSL", package: "OpenSSL-Package"),
                .product(name: "K1", package: "k1"),
                .product(name: "SwiftCurve448", package: "swift-curve448"),
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
