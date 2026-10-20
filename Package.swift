// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "WantasticMac",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "WantasticCore", targets: ["WantasticCore"]),
        .executable(name: "Wantastic", targets: ["WantasticApp"]),
        .library(name: "WantasticTunnel", targets: ["WantasticTunnel"]),
        .library(name: "WantasticLocalAccessHelperCore", targets: ["WantasticLocalAccessHelperCore"]),
        .executable(name: "WantasticLocalAccessHelper", targets: ["WantasticLocalAccessHelper"]),
    ],
    targets: [
        .target(name: "WantasticCore"),
        .executableTarget(
            name: "WantasticApp",
            dependencies: ["WantasticCore", "WantasticTunnel"],
            resources: [.process("Resources")]
        ),
        .target(name: "WantasticTunnel", dependencies: ["WantasticCore"]),
        .target(name: "WantasticLocalAccessHelperCore", dependencies: ["WantasticCore"]),
        .executableTarget(name: "WantasticLocalAccessHelper", dependencies: ["WantasticLocalAccessHelperCore"]),
        .testTarget(name: "WantasticCoreTests", dependencies: [
            "WantasticCore", "WantasticTunnel", "WantasticLocalAccessHelperCore",
        ]),
    ]
)
