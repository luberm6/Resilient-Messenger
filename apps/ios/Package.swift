// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "ResilientMessenger",
    platforms: [.iOS(.v17)],
    products: [.library(name: "ResilientMessengerApp", targets: ["ResilientMessengerApp"])],
    targets: [
        .target(name: "ResilientMessengerApp"),
        .testTarget(name: "ResilientMessengerAppTests", dependencies: ["ResilientMessengerApp"]),
    ]
)
