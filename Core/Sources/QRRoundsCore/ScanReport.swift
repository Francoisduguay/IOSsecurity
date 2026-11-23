import Foundation
import CryptoKit

/// A GPS position as reported by the phone.
public struct GeoFix: Codable, Equatable, Sendable {
    public let latitude: Double
    public let longitude: Double
    /// Radius of uncertainty, in meters (smaller is better).
    public let accuracyMeters: Double

    public init(latitude: Double, longitude: Double, accuracyMeters: Double) {
        self.latitude = latitude
        self.longitude = longitude
        self.accuracyMeters = accuracyMeters
    }

    /// True if this position can exist on Earth. A position that can't exist means a bug or a
    /// hacked phone, so the station refuses the scan instead of writing nonsense into the round log.
    /// NaN is never plausible: every comparison with NaN is false.
    public var isPlausible: Bool {
        (-90.0...90.0).contains(latitude)
            && (-180.0...180.0).contains(longitude)
            && accuracyMeters.isFinite
            && accuracyMeters >= 0
    }
}

/// What the phone says about one scan: "I scanned this checkpoint code, at this time, at this place".
///
/// Threats addressed (STRIDE):
/// - tampering and repudiation: the report is signed with the guard's key (see `SignedScan`);
/// - replay: `nonce`, `scannedAtMillis` and `counter` let the station refuse a scan sent twice
///   (see `ReplayGuard`).
public struct ScanReport: Codable, Equatable, Sendable {
    public static let currentVersion = 1

    public let version: Int
    /// The QR code text exactly as scanned, so the station can check the station signature itself.
    public let checkpointCode: String
    /// The phone's clock, in milliseconds since 1970.
    public let scannedAtMillis: Int64
    /// Nil if the phone had no GPS fix: the scan still counts, with a warning in the round log.
    public let location: GeoFix?
    /// 16 random bytes, different for every scan: two scans can never be identical.
    public let nonce: Data
    /// 1, 2, 3… per phone. A number that goes backwards is a replay; a gap is a scan that never arrived.
    public let counter: UInt64

    public init(version: Int = ScanReport.currentVersion, checkpointCode: String, scannedAtMillis: Int64,
                location: GeoFix?, nonce: Data, counter: UInt64) {
        self.version = version
        self.checkpointCode = checkpointCode
        self.scannedAtMillis = scannedAtMillis
        self.location = location
        self.nonce = nonce
        self.counter = counter
    }

    /// `scannedAtMillis` as a date.
    public var scannedAt: Date {
        Date(timeIntervalSince1970: TimeInterval(scannedAtMillis) / 1000)
    }
}

/// A scan report as it travels from the phone to the station.
///
/// `report` holds the exact JSON bytes that were signed. The station checks the signature over
/// these bytes and never re-encodes the JSON: two encoders can write the same report differently
/// (key order, spacing), and a signature is only valid for the exact bytes it was made over.
public struct SignedScan: Codable, Equatable, Sendable {
    /// The report, as JSON.
    public let report: Data
    /// ECDSA P-256 signature, raw format (64 bytes), over `"QRR1-SCAN\0" + report`.
    public let signature: Data

    public init(report: Data, signature: Data) {
        self.report = report
        self.signature = signature
    }

    /// Label signed together with the report ("domain separation", same idea as `CheckpointCode`):
    /// a signature made for a scan can't be reused as a signature for anything else in the project.
    static let domain = Data("QRR1-SCAN\u{0}".utf8)
}

/// Anything that can sign with the guard's private key.
///
/// In the iOS app this will be a Secure Enclave key that needs Face ID for every signature.
public protocol ScanSigner {
    var publicKey: P256.Signing.PublicKey { get }
    /// Returns the raw (64-byte) ECDSA P-256 signature of `data`.
    func signature(for data: Data) throws -> Data
}

/// FOR TESTS AND THE SIMULATOR ONLY: a guard key kept in ordinary memory.
///
/// Malware or a debugger could copy this key and sign scans without the guard. On a real iPhone,
/// the key must live in the Secure Enclave (it can never leave the chip) and every signature must
/// require Face ID. That version comes later, in the iOS app.
public struct SoftwareSigner: ScanSigner {
    private let privateKey: P256.Signing.PrivateKey

    public init() {
        privateKey = P256.Signing.PrivateKey()
    }

    public var publicKey: P256.Signing.PublicKey { privateKey.publicKey }

    public func signature(for data: Data) throws -> Data {
        try privateKey.signature(for: data).rawRepresentation
    }
}

/// Phone side: a scan report that is ready to be signed.
public struct ScanDraft: Sendable {
    /// The checkpoint, already verified: the app can show "Main entrance: confirm with Face ID".
    public let checkpoint: Checkpoint
    public let report: ScanReport
    /// The report encoded once. These exact bytes are signed and sent.
    public let reportBytes: Data

    /// The bytes the guard's key must sign: `"QRR1-SCAN\0" + reportBytes`.
    public var signingInput: Data { SignedScan.domain + reportBytes }

    /// Checks the QR code, then builds the report.
    ///
    /// The station signature is checked FIRST: the phone refuses a fake QR code before it asks the
    /// guard for Face ID, so a guard is never asked to sign a scan of a fake checkpoint.
    /// Throws `CheckpointCodeError` if the code is fake or not one of ours.
    public static func make(checkpointCode: String, stationKey: P256.Signing.PublicKey,
                            location: GeoFix?, counter: UInt64, now: Date = Date()) throws -> ScanDraft {
        let checkpoint = try CheckpointCode.verify(checkpointCode, stationKey: stationKey)
        let report = ScanReport(
            checkpointCode: checkpointCode,
            scannedAtMillis: Int64((now.timeIntervalSince1970 * 1000).rounded()),
            location: location,
            nonce: randomNonce(),
            counter: counter
        )
        return ScanDraft(checkpoint: checkpoint, report: report, reportBytes: try JSONEncoder().encode(report))
    }

    /// Signs the report. With the Secure Enclave signer, this is where Face ID is asked.
    public func signed(with signer: some ScanSigner) throws -> SignedScan {
        SignedScan(report: reportBytes, signature: try signer.signature(for: signingInput))
    }

    /// 16 bytes from CryptoKit's secure random generator.
    private static func randomNonce() -> Data {
        SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) }
    }
}
