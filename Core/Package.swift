// swift-tools-version:5.9
import PackageDescription

// QRRoundsCore holds the security logic shared by the iPhone app and the Mac app.
// No UI and no networking here, so everything can be unit-tested with `swift test`.
// No third-party dependencies: the only crypto library is Apple's CryptoKit.
let package = Package(
    name: "QRRoundsCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "QRRoundsCore", targets: ["QRRoundsCore"]),
    ],
    targets: [
        .target(name: "QRRoundsCore"),
        .testTarget(name: "QRRoundsCoreTests", dependencies: ["QRRoundsCore"]),
    ]
)
