// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "eudi-wallet-oidc-ios",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "eudi-wallet-oidc-ios",
            targets: ["eudi-wallet-oidc-ios"]),
    ],
    dependencies: [
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", branch: "master"),
        .package(name: "KeychainSwift", url: "https://github.com/evgenyneu/keychain-swift.git", from: "21.0.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.1"),
        .package(url: "https://github.com/decentralised-dataexchange/PresentationExchangeSdkiOS.git", .upToNextMajor(from: "2024.3.1"))
    ],
    targets: [
        .target(
            name: "eudi-wallet-oidc-ios",
            dependencies: ["Base58Swift", "KeychainSwift", "CryptoSwift", "PresentationExchangeSdkiOS"],
            path: "Sources"),
        .testTarget(
            name: "eudi-wallet-oidc-iosTests",
            dependencies: ["eudi-wallet-oidc-ios"]),
    ]
)
