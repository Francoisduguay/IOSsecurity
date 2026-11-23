import Foundation

/// Anti-replay memory for ONE phone, kept by the station.
///
/// Threat addressed: someone records a genuine signed scan (on the network, or from the phone) and
/// sends it again later, to "prove" a visit that did not happen. The signature is still valid, so
/// the signature alone can't stop this. Three checks do:
/// 1. timestamp: an old scan is refused, so a recording only works for `maxClockSkew` seconds;
/// 2. nonce: inside that window, the same scan can't be accepted twice;
/// 3. counter: the phone numbers its scans 1, 2, 3…, so an old scan is refused even if its
///    nonce was forgotten.
public struct ReplayGuard: Sendable {
    /// How far the phone's clock may be from the station's clock, in seconds (default 120 s).
    public let maxClockSkew: TimeInterval
    /// The highest counter accepted so far (0 = no scan yet).
    public private(set) var lastCounter: UInt64 = 0
    /// Nonces accepted recently, with the time written inside their scan.
    private var recentNonces: [Data: Date] = [:]

    public init(maxClockSkew: TimeInterval = 120) {
        self.maxClockSkew = maxClockSkew
    }

    /// How many nonces are remembered right now (it stays small: old ones are forgotten).
    public var rememberedNonceCount: Int { recentNonces.count }

    /// Accepts a scan, or throws `ReplayError`. Nothing is remembered when it throws.
    /// - Returns: how many counter numbers were skipped. More than 0 means scans that never arrived.
    @discardableResult
    public mutating func check(nonce: Data, counter: UInt64, scannedAt: Date, now: Date) throws -> UInt64 {
        // 1. Timestamp, in both directions: too old is a replay, too far in the future is a
        //    scan prepared in advance.
        guard abs(scannedAt.timeIntervalSince(now)) <= maxClockSkew else {
            throw ReplayError.staleTimestamp
        }

        // Forget nonces whose scan is now too old: replaying that scan would fail check 1 anyway,
        // because the time inside it is signed. This keeps memory bounded.
        recentNonces = recentNonces.filter { now.timeIntervalSince($0.value) <= maxClockSkew }

        // 2. Nonce: the same scan twice inside the window.
        guard recentNonces[nonce] == nil else {
            throw ReplayError.replayedNonce
        }

        // 3. Counter: must go up. Equal or lower means an old scan.
        guard counter > lastCounter else {
            throw ReplayError.counterRollback
        }

        let skipped = counter - lastCounter - 1
        lastCounter = counter
        recentNonces[nonce] = scannedAt
        return skipped
    }
}

public enum ReplayError: Error, Equatable {
    /// The scan's time is more than `maxClockSkew` away from the station's clock.
    case staleTimestamp
    /// This exact scan was already accepted.
    case replayedNonce
    /// The counter did not go up: an old scan sent again.
    case counterRollback
}
