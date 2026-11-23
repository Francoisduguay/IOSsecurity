import XCTest
import CryptoKit
import QRRoundsCore

/// Station side: every way a scan can be refused, and the scans that must be accepted.
final class ScanVerifierTests: XCTestCase {
    private static let office = GeoFix(latitude: 48.8566, longitude: 2.3522, accuracyMeters: 8)
    private let stationKey = P256.Signing.PrivateKey()
    private let phone = SoftwareSigner()
    private let entrance = Checkpoint(id: "CP-01", name: "Main entrance")
    /// Fixed station clock.
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func makeStation() -> ScanVerifier {
        let fixedNow = now
        return ScanVerifier(stationKey: stationKey.publicKey, now: { fixedNow })
    }

    /// An honest phone scanning a genuine QR code.
    private func scan(counter: UInt64, location: GeoFix? = office, at time: Date? = nil,
                      by signer: SoftwareSigner? = nil) throws -> SignedScan {
        let code = try CheckpointCode.make(for: entrance, signingKey: stationKey)
        let draft = try ScanDraft.make(checkpointCode: code, stationKey: stationKey.publicKey,
                                       location: location, counter: counter, now: time ?? now)
        return try draft.signed(with: signer ?? phone)
    }

    /// A hacked phone: builds any report it wants and signs it correctly, skipping its own checks.
    private func hackedPhoneSigns(_ report: ScanReport) throws -> SignedScan {
        let bytes = try JSONEncoder().encode(report)
        return SignedScan(report: bytes, signature: try phone.signature(for: Data("QRR1-SCAN\u{0}".utf8) + bytes))
    }

    private func genuineReport(counter: UInt64) throws -> ScanReport {
        ScanReport(checkpointCode: try CheckpointCode.make(for: entrance, signingKey: stationKey),
                   scannedAtMillis: 1_800_000_000_000, location: Self.office,
                   nonce: Data((0..<16).map { _ in UInt8.random(in: 0...255) }), counter: counter)
    }

    private func rejection(_ verdict: ScanVerdict) -> ScanRejection? {
        if case .rejected(let reason) = verdict { return reason }
        return nil
    }

    private func accepted(_ verdict: ScanVerdict) -> AcceptedScan? {
        if case .accepted(let scan) = verdict { return scan }
        return nil
    }

    // MARK: Accepted

    func testGenuineScanIsAccepted() throws {
        var station = makeStation()
        let result = try XCTUnwrap(accepted(station.verify(try scan(counter: 1), guardKey: phone.publicKey)))
        XCTAssertEqual(result.checkpoint, entrance)
        XCTAssertEqual(result.report.location, Self.office)
        XCTAssertEqual(result.warnings, [])
    }

    func testScanWithoutGPSIsAcceptedWithWarning() throws {
        var station = makeStation()
        let result = try XCTUnwrap(accepted(station.verify(try scan(counter: 1, location: nil),
                                                           guardKey: phone.publicKey)))
        XCTAssertEqual(result.warnings, [.noLocation])
    }

    /// Scans 2 and 3 never arrived: scan 4 is accepted, and the log says 2 are missing.
    func testCounterGapIsAcceptedWithWarning() throws {
        var station = makeStation()
        XCTAssertNotNil(accepted(station.verify(try scan(counter: 1), guardKey: phone.publicKey)))
        let result = try XCTUnwrap(accepted(station.verify(try scan(counter: 4), guardKey: phone.publicKey)))
        XCTAssertEqual(result.warnings, [.skippedCounters(2)])
    }

    /// Each phone has its own counter: phone B's scan 1 is not a replay of phone A's scan 1.
    func testTwoPhonesKeepSeparateCounters() throws {
        var station = makeStation()
        let phoneB = SoftwareSigner()
        XCTAssertNotNil(accepted(station.verify(try scan(counter: 1), guardKey: phone.publicKey)))
        XCTAssertNotNil(accepted(station.verify(try scan(counter: 1, by: phoneB), guardKey: phoneB.publicKey)))
        XCTAssertNotNil(accepted(station.verify(try scan(counter: 2), guardKey: phone.publicKey)))
        XCTAssertEqual(rejection(station.verify(try scan(counter: 1, by: phoneB), guardKey: phoneB.publicKey)),
                       .counterRollback)
    }

    // MARK: Tampering and spoofing

    /// Tampering: the GPS position is moved after signing, the signature is kept.
    func testReportChangedAfterSigningIsRejected() throws {
        var station = makeStation()
        let genuine = try scan(counter: 1)
        let report = try JSONDecoder().decode(ScanReport.self, from: genuine.report)
        let moved = ScanReport(checkpointCode: report.checkpointCode, scannedAtMillis: report.scannedAtMillis,
                               location: GeoFix(latitude: 48.9000, longitude: 2.3522, accuracyMeters: 8),
                               nonce: report.nonce, counter: report.counter)
        let tampered = SignedScan(report: try JSONEncoder().encode(moved), signature: genuine.signature)
        XCTAssertEqual(rejection(station.verify(tampered, guardKey: phone.publicKey)), .badSignature)
    }

    /// Spoofing: a colleague's phone signs the scan, but it is sent as this guard's scan.
    func testScanSignedByAnotherPhoneIsRejected() throws {
        var station = makeStation()
        let otherPhone = SoftwareSigner()
        XCTAssertEqual(rejection(station.verify(try scan(counter: 1, by: otherPhone), guardKey: phone.publicKey)),
                       .badSignature)
    }

    /// Domain separation: a signature over the bare report, without the "QRR1-SCAN" label, does not count.
    func testSignatureWithoutScanLabelIsRejected() throws {
        var station = makeStation()
        let bytes = try JSONEncoder().encode(try genuineReport(counter: 1))
        let unlabeled = SignedScan(report: bytes, signature: try phone.signature(for: bytes))
        XCTAssertEqual(rejection(station.verify(unlabeled, guardKey: phone.publicKey)), .badSignature)
    }

    /// A hacked phone skips its own QR check and signs a scan of a fake checkpoint code.
    func testHackedPhoneWithFakeCheckpointIsRejected() throws {
        var station = makeStation()
        let fakeCode = try CheckpointCode.make(for: entrance, signingKey: P256.Signing.PrivateKey())
        let report = ScanReport(checkpointCode: fakeCode, scannedAtMillis: 1_800_000_000_000,
                                location: Self.office, nonce: Data(repeating: 7, count: 16), counter: 1)
        XCTAssertEqual(rejection(station.verify(try hackedPhoneSigns(report), guardKey: phone.publicKey)),
                       .forgedCheckpoint)
    }

    /// A refused scan is still used up: sending the same bytes again does not get a second try.
    func testRefusedScanCannotBeRetried() throws {
        var station = makeStation()
        let fakeCode = try CheckpointCode.make(for: entrance, signingKey: P256.Signing.PrivateKey())
        let forged = try hackedPhoneSigns(ScanReport(checkpointCode: fakeCode, scannedAtMillis: 1_800_000_000_000,
                                                     location: Self.office, nonce: Data(repeating: 7, count: 16),
                                                     counter: 1))
        XCTAssertEqual(rejection(station.verify(forged, guardKey: phone.publicKey)), .forgedCheckpoint)
        XCTAssertEqual(rejection(station.verify(forged, guardKey: phone.publicKey)), .replayedNonce)
    }

    // MARK: Malformed reports

    func testImpossibleLatitudeIsRejected() throws {
        var station = makeStation()
        let badGPS = GeoFix(latitude: 200, longitude: 2.3522, accuracyMeters: 8)
        XCTAssertEqual(rejection(station.verify(try scan(counter: 1, location: badGPS), guardKey: phone.publicKey)),
                       .malformedReport)
    }

    func testUnknownVersionIsRejected() throws {
        var station = makeStation()
        let genuine = try genuineReport(counter: 1)
        let report = ScanReport(version: 2, checkpointCode: genuine.checkpointCode,
                                scannedAtMillis: genuine.scannedAtMillis, location: genuine.location,
                                nonce: genuine.nonce, counter: genuine.counter)
        XCTAssertEqual(rejection(station.verify(try hackedPhoneSigns(report), guardKey: phone.publicKey)),
                       .malformedReport)
    }

    // MARK: Replay

    func testSameScanTwiceIsRejected() throws {
        var station = makeStation()
        let once = try scan(counter: 1)
        XCTAssertNotNil(accepted(station.verify(once, guardKey: phone.publicKey)))
        XCTAssertEqual(rejection(station.verify(once, guardKey: phone.publicKey)), .replayedNonce)
    }

    func testCounterNotIncreasingIsRejected() throws {
        var station = makeStation()
        XCTAssertNotNil(accepted(station.verify(try scan(counter: 5), guardKey: phone.publicKey)))
        XCTAssertEqual(rejection(station.verify(try scan(counter: 5), guardKey: phone.publicKey)), .counterRollback)
        XCTAssertEqual(rejection(station.verify(try scan(counter: 3), guardKey: phone.publicKey)), .counterRollback)
    }

    func testTenMinuteOldScanIsRejected() throws {
        var station = makeStation()
        let old = try scan(counter: 1, at: now.addingTimeInterval(-600))
        XCTAssertEqual(rejection(station.verify(old, guardKey: phone.publicKey)), .staleTimestamp)
    }

    func testScanDatedInTheFutureIsRejected() throws {
        var station = makeStation()
        let future = try scan(counter: 1, at: now.addingTimeInterval(600))
        XCTAssertEqual(rejection(station.verify(future, guardKey: phone.publicKey)), .staleTimestamp)
    }
}
