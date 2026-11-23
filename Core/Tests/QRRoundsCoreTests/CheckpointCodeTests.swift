import XCTest
import CryptoKit
import QRRoundsCore

final class CheckpointCodeTests: XCTestCase {
    private let stationKey = P256.Signing.PrivateKey()
    private let entrance = Checkpoint(id: "CP-01", name: "Main entrance")

    func testGenuineCodeIsAccepted() throws {
        let code = try CheckpointCode.make(for: entrance, signingKey: stationKey)
        XCTAssertTrue(code.hasPrefix("QRR1C."))
        XCTAssertEqual(try CheckpointCode.verify(code, stationKey: stationKey.publicKey), entrance)
    }

    /// Spoofing: a "fake Mac" with its own key prints a QR code for our checkpoint.
    func testCodeFromAnotherStationIsRejected() throws {
        let fakeStationKey = P256.Signing.PrivateKey()
        let fakeCode = try CheckpointCode.make(for: entrance, signingKey: fakeStationKey)
        XCTAssertThrowsError(try CheckpointCode.verify(fakeCode, stationKey: stationKey.publicKey)) { error in
            XCTAssertEqual(error as? CheckpointCodeError, .invalidSignature)
        }
    }

    /// Tampering: someone edits the checkpoint inside the code but keeps the original signature.
    func testModifiedCodeIsRejected() throws {
        let code = try CheckpointCode.make(for: entrance, signingKey: stationKey)
        let parts = code.dropFirst(CheckpointCode.prefix.count).split(separator: ".")
        let payload = try XCTUnwrap(Data(base64URLEncoded: String(parts[0])))
        let edited = Data(String(decoding: payload, as: UTF8.self)
            .replacingOccurrences(of: "Main entrance", with: "Back door").utf8)
        let tamperedCode = CheckpointCode.prefix + edited.base64URLEncodedString() + "." + String(parts[1])
        XCTAssertThrowsError(try CheckpointCode.verify(tamperedCode, stationKey: stationKey.publicKey)) { error in
            XCTAssertEqual(error as? CheckpointCodeError, .invalidSignature)
        }
    }

    /// Domain separation: a signature over the bare payload, without the label, does not count.
    func testSignatureWithoutDomainLabelIsRejected() throws {
        let payload = try JSONEncoder().encode(entrance)
        let signature = try stationKey.signature(for: payload)
        let code = CheckpointCode.prefix + payload.base64URLEncodedString() + "."
            + signature.rawRepresentation.base64URLEncodedString()
        XCTAssertThrowsError(try CheckpointCode.verify(code, stationKey: stationKey.publicKey)) { error in
            XCTAssertEqual(error as? CheckpointCodeError, .invalidSignature)
        }
    }

    /// Other QR codes (a website, random text, a damaged or huge code) are not mistaken for checkpoints.
    func testOtherQRCodesAreRejected() {
        let samples = ["", "hello", "https://example.com", "QRR1C.", "QRR1C.abc", "QRR1C.a.b.c",
                       "QRR1C.abcd.efgh", String(repeating: "A", count: 5_000)]
        for text in samples {
            XCTAssertThrowsError(try CheckpointCode.verify(text, stationKey: stationKey.publicKey),
                                 "Accepted: \(text.prefix(20))")
        }
    }
}
