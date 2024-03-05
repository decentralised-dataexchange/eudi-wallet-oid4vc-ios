// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "eudi-wallet-oidc-ios",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "eudi-wallet-oidc-ios",
            targets: ["eudi-wallet-oidc-ios"]),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "eudi-wallet-oidc-ios",
            dependencies: [],
            path: "Sources"),
        .testTarget(
            name: "eudi-wallet-oidc-iosTests",
            dependencies: ["eudi-wallet-oidc-ios"]),
    ]
)
