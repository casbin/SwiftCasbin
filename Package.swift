// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Casbin",
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "Casbin",
            targets: ["Casbin"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/nicklockwood/Expression.git",.upToNextMajor(from: "0.13.0")),
        .package(url: "https://github.com/sharplet/Regex.git", from: "2.1.0"),
        .package(url: "https://github.com/apple/swift-nio", from: "2.0.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services", from: "1.5.1"),
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
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services")
                
            ]
            
        ),
           
        .testTarget(
            name: "CasbinTests",
            dependencies: ["Casbin"],
            resources: [.copy("examples")]
        ),
    ]
)
