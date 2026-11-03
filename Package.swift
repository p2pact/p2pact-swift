// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "P2PACT",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "P2PACT", targets: ["P2PACT"]),
        .executable(name: "p2pact-interop", targets: ["p2pact-interop"]),
    ],
    dependencies: [
        // zstd (with its dictionary builder): Facebook's own Package.swift
        .package(url: "https://github.com/facebook/zstd", from: "1.5.7"),
    ],
    targets: [
        .target(
            name: "P2PACT",
            dependencies: [.product(name: "libzstd", package: "zstd")],
            resources: [.copy("Resources/common-1.zdict")]
        ),
        .executableTarget(name: "p2pact-interop", dependencies: ["P2PACT"]),
        .testTarget(name: "P2PACTTests", dependencies: ["P2PACT"]),
    ],
    swiftLanguageVersions: [.v5]
)
