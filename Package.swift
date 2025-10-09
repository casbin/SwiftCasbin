// swift-tools-version:6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Casbin",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "Casbin",
            targets: ["Casbin"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/nicklockwood/Expression.git",.upToNextMajor(from: "0.13.0")),
        .package(url: "https://github.com/sharplet/Regex.git", from: "2.1.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(name: "IpParser"),
        .target(
            name: "Casbin",
            dependencies: [
                .target(name: "IpParser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Expression", package: "Expression"),
                .product(name: "Regex", package: "Regex"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency")
            ]
        ),
        .testTarget(
            name: "CasbinTests",
            dependencies: ["Casbin"],
            resources: [.copy("examples")]
        ),
    ]
)
