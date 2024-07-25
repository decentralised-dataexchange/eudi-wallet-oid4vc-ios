// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "eudiWalletOidcIos",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "eudiWalletOidcIos",
            targets: ["eudiWalletOidcIos"]),
    ],
    dependencies: [
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", branch: "master"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.1"),
        .package(url: "https://github.com/decentralised-dataexchange/PresentationExchangeSdkiOS.git", .upToNextMajor(from: "2024.3.1")),
        .package(url: "https://github.com/airsidemobile/JOSESwift.git", from: "2.3.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from:"3.5.2")
    ],
    targets: [
        .target(
            name: "eudiWalletOidcIos",
            dependencies: ["Base58Swift", "CryptoSwift", "PresentationExchangeSdkiOS", "JOSESwift", .product(name: "Crypto", package: "swift-crypto")],
            path: "Sources"),
        .testTarget(
            name: "eudi-wallet-oidc-iosTests",
            dependencies: ["eudiWalletOidcIos"]),
    ]
)
