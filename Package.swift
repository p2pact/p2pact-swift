// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "P2PACT",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "P2PACT", targets: ["P2PACT"]),
        .library(name: "P2PACTClient", targets: ["P2PACTClient"]),
        .executable(name: "p2pact-interop", targets: ["p2pact-interop"]),
        .executable(name: "p2pact-client-cli", targets: ["ClientCLI"]),
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
        .target(name: "P2PACTClient", dependencies: ["P2PACT"]),
        .executableTarget(name: "ClientCLI", dependencies: ["P2PACTClient"], path: "Examples/ClientCLI"),
        .testTarget(name: "P2PACTTests", dependencies: ["P2PACT"]),
        .testTarget(
            name: "P2PACTClientTests",
            dependencies: ["P2PACTClient", "P2PACT"],
            resources: [.copy("Resources/tools")]
        ),
    ],
    swiftLanguageVersions: [.v5]
)
