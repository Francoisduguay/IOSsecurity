import XCTest
import QRRoundsCore

final class ReplayGuardTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    /// Memory stays bounded: once a scan is older than the window, its nonce is forgotten
    /// (replaying it would fail the timestamp check anyway).
    func testOldNoncesAreForgotten() throws {
        var replayGuard = ReplayGuard()
        try replayGuard.check(nonce: Data(repeating: 1, count: 16), counter: 1, scannedAt: now, now: now)
        XCTAssertEqual(replayGuard.rememberedNonceCount, 1)

        let later = now.addingTimeInterval(600)
        try replayGuard.check(nonce: Data(repeating: 2, count: 16), counter: 2, scannedAt: later, now: later)
        XCTAssertEqual(replayGuard.rememberedNonceCount, 1)

        // The forgotten scan is still refused, by its timestamp.
        XCTAssertThrowsError(try replayGuard.check(nonce: Data(repeating: 1, count: 16), counter: 1,
                                                   scannedAt: now, now: later)) { error in
            XCTAssertEqual(error as? ReplayError, .staleTimestamp)
        }
    }
}
