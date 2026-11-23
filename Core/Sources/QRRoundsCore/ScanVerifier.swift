import Foundation
import CryptoKit

/// Station side: decides whether a signed scan goes into the round log.
public struct ScanVerifier {
    public let stationKey: P256.Signing.PublicKey
    public let maxClockSkew: TimeInterval
    /// The station's clock. Injected so tests can use a fixed time.
    private let now: () -> Date
    /// One replay memory per phone, keyed by the phone's public key.
    private var replayGuards: [Data: ReplayGuard] = [:]

    public init(stationKey: P256.Signing.PublicKey, maxClockSkew: TimeInterval = 120,
                now: @escaping () -> Date = Date.init) {
        self.stationKey = stationKey
        self.maxClockSkew = maxClockSkew
        self.now = now
    }

    /// Checks a scan received from the phone whose public key is `guardKey` (known from pairing).
    public mutating func verify(_ scan: SignedScan, guardKey: P256.Signing.PublicKey) -> ScanVerdict {
        // 1. The guard's signature, over the exact bytes received. Nothing in the report is trusted
        //    (or even parsed) before this. The JSON is never re-encoded to verify: the signature is
        //    only valid for the exact bytes the phone signed.
        guard let signature = try? P256.Signing.ECDSASignature(rawRepresentation: scan.signature),
              guardKey.isValidSignature(signature, for: SignedScan.domain + scan.report) else {
            return .rejected(.badSignature)
        }

        // 2. Decode, then check the version and that the position can exist. The bytes are authentic,
        //    but a buggy or hacked phone can still sign nonsense.
        guard let report = try? JSONDecoder().decode(ScanReport.self, from: scan.report),
              report.version == ScanReport.currentVersion,
              report.location?.isPlausible ?? true else {
            return .rejected(.malformedReport)
        }

        // 3. Replay checks, with this phone's own memory (each phone has its own counter).
        let phoneID = guardKey.x963Representation
        var replayGuard = replayGuards[phoneID] ?? ReplayGuard(maxClockSkew: maxClockSkew)
        let skipped: UInt64
        do {
            skipped = try replayGuard.check(nonce: report.nonce, counter: report.counter,
                                            scannedAt: report.scannedAt, now: now())
        } catch let error as ReplayError {
            return .rejected(ScanRejection(error))
        } catch {
            return .rejected(.malformedReport) // Not reachable: check(...) only throws ReplayError.
        }
        // Saved now, BEFORE check 4: even if this scan is refused below, its nonce and counter are
        // used up, so these bytes can never be accepted later.
        replayGuards[phoneID] = replayGuard

        // 4. The checkpoint code inside the report must be signed by THIS station. The phone checked
        //    it too, but a hacked phone can skip its own check: the station never trusts it.
        guard let checkpoint = try? CheckpointCode.verify(report.checkpointCode, stationKey: stationKey) else {
            return .rejected(.forgedCheckpoint)
        }

        var warnings: [ScanWarning] = []
        if skipped > 0 { warnings.append(.skippedCounters(skipped)) }
        if report.location == nil { warnings.append(.noLocation) }
        return .accepted(AcceptedScan(checkpoint: checkpoint, report: report, warnings: warnings))
    }
}

public enum ScanVerdict: Equatable, Sendable {
    case accepted(AcceptedScan)
    case rejected(ScanRejection)
}

/// A scan that passed every check, ready for the round log.
public struct AcceptedScan: Equatable, Sendable {
    public let checkpoint: Checkpoint
    public let report: ScanReport
    /// Accepted, but the supervisor should look at it.
    public let warnings: [ScanWarning]
}

public enum ScanWarning: Equatable, Sendable, CustomStringConvertible {
    /// Counter numbers were skipped: that many scans from this phone never arrived.
    case skippedCounters(UInt64)
    /// The phone had no GPS fix for this scan.
    case noLocation

    public var description: String {
        switch self {
        case .skippedCounters(let count):
            return "\(count) earlier scan(s) from this phone never arrived."
        case .noLocation:
            return "The phone had no GPS position for this scan."
        }
    }
}

public enum ScanRejection: Error, Equatable, Sendable, CustomStringConvertible {
    case badSignature
    case malformedReport
    case staleTimestamp
    case replayedNonce
    case counterRollback
    case forgedCheckpoint

    init(_ error: ReplayError) {
        switch error {
        case .staleTimestamp: self = .staleTimestamp
        case .replayedNonce: self = .replayedNonce
        case .counterRollback: self = .counterRollback
        }
    }

    /// One sentence for the round log.
    public var description: String {
        switch self {
        case .badSignature:
            return "Refused: the scan was not signed by this guard's phone, or was changed after signing."
        case .malformedReport:
            return "Refused: the scan report is unreadable, has an unknown version, or an impossible GPS position."
        case .staleTimestamp:
            return "Refused: the scan's time is too far from the station's clock (old or replayed scan)."
        case .replayedNonce:
            return "Refused: this exact scan was already received (replay)."
        case .counterRollback:
            return "Refused: the scan number did not go up, so this is an old scan sent again."
        case .forgedCheckpoint:
            return "Refused: the checkpoint QR code in the scan was not signed by this station."
        }
    }
}
