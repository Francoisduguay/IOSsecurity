import XCTest
import CryptoKit
import QRRoundsCore

/// Phone side: building and signing scan reports.
final class ScanReportTests: XCTestCase {
    private let stationKey = P256.Signing.PrivateKey()
    private let phone = SoftwareSigner()
    private let entrance = Checkpoint(id: "CP-01", name: "Main entrance")
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    /// The draft holds the code exactly as scanned, 16 random bytes, and signs "QRR1-SCAN\0" + report.
    func testDraftIsBuiltAndSigned() throws {
        let code = try CheckpointCode.make(for: entrance, signingKey: stationKey)
        let draft = try ScanDraft.make(checkpointCode: code, stationKey: stationKey.publicKey,
                                       location: nil, counter: 1, now: now)
        XCTAssertEqual(draft.checkpoint, entrance)
        XCTAssertEqual(draft.report.version, 1)
        XCTAssertEqual(draft.report.checkpointCode, code)
        XCTAssertEqual(draft.report.scannedAtMillis, 1_800_000_000_000)
        XCTAssertEqual(draft.report.nonce.count, 16)
        XCTAssertEqual(draft.signingInput, Data("QRR1-SCAN\u{0}".utf8) + draft.reportBytes)

        let scan = try draft.signed(with: phone)
        XCTAssertEqual(scan.report, draft.reportBytes)
        XCTAssertEqual(scan.signature.count, 64)

        let other = try ScanDraft.make(checkpointCode: code, stationKey: stationKey.publicKey,
                                       location: nil, counter: 1, now: now)
        XCTAssertNotEqual(other.report.nonce, draft.report.nonce, "Every scan needs a new nonce")
    }

    /// Spoofing: the phone refuses a fake QR code before it asks for Face ID (no draft, so nothing to sign).
    func testPhoneRefusesFakeCheckpointBeforeSigning() throws {
        let fakeStationKey = P256.Signing.PrivateKey()
        let fakeCode = try CheckpointCode.make(for: entrance, signingKey: fakeStationKey)
        XCTAssertThrowsError(try ScanDraft.make(checkpointCode: fakeCode, stationKey: stationKey.publicKey,
                                                location: nil, counter: 1, now: now)) { error in
            XCTAssertEqual(error as? CheckpointCodeError, .invalidSignature)
        }
    }

    /// Positions that can't exist on Earth are not plausible. NaN never is.
    func testGeoFixPlausibility() {
        XCTAssertTrue(GeoFix(latitude: 48.8566, longitude: 2.3522, accuracyMeters: 8).isPlausible)
        XCTAssertTrue(GeoFix(latitude: -90, longitude: 180, accuracyMeters: 0).isPlausible)
        XCTAssertFalse(GeoFix(latitude: 200, longitude: 2.3522, accuracyMeters: 8).isPlausible)
        XCTAssertFalse(GeoFix(latitude: 48.8566, longitude: -181, accuracyMeters: 8).isPlausible)
        XCTAssertFalse(GeoFix(latitude: 48.8566, longitude: 2.3522, accuracyMeters: -1).isPlausible)
        XCTAssertFalse(GeoFix(latitude: 48.8566, longitude: 2.3522, accuracyMeters: .nan).isPlausible)
        XCTAssertFalse(GeoFix(latitude: 48.8566, longitude: 2.3522, accuracyMeters: .infinity).isPlausible)
        XCTAssertFalse(GeoFix(latitude: .nan, longitude: 2.3522, accuracyMeters: 8).isPlausible)
    }
}
