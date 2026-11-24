// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "BaoBuddy",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "BaoBuddyCore",
            targets: ["BaoBuddyCore"]
        ),
        .library(
            name: "BaoBuddySSH",
            targets: ["BaoBuddySSH"]
        ),
        .executable(
            name: "BaoBuddyHelper",
            targets: ["BaoBuddyHelper"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssh.git", from: "0.15.1")
    ],
    targets: [
        .target(
            name: "BaoBuddyCore",
            path: "Sources/BaoBuddyCore"
        ),
        .target(
            name: "BaoBuddySSH",
            dependencies: [
                "BaoBuddyCore",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSH", package: "swift-nio-ssh")
            ],
            path: "Sources/BaoBuddySSH"
        ),
        .executableTarget(
            name: "BaoBuddyHelper",
            dependencies: ["BaoBuddyCore", "BaoBuddySSH"],
            path: "Sources/BaoBuddyHelper"
        ),
        .testTarget(
            name: "BaoBuddyCoreTests",
            dependencies: ["BaoBuddyCore"],
            path: "Tests/BaoBuddyCoreTests"
        ),
        .testTarget(
            name: "BaoBuddySSHTests",
            dependencies: [
                "BaoBuddySSH",
                "BaoBuddyCore",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOSSH", package: "swift-nio-ssh")
            ],
            path: "Tests/BaoBuddySSHTests"
        ),
        .testTarget(
            name: "BaoBuddyHelperTests",
            dependencies: [
                "BaoBuddyHelper",
                "BaoBuddyCore"
            ],
            path: "Tests/BaoBuddyHelperTests"
        )
    ]
)
