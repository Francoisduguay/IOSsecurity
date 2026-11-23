import Foundation
import CryptoKit

/// A place the guard must visit during a round.
public struct Checkpoint: Codable, Equatable, Sendable {
    public let id: String
    public let name: String

    public init(id: String, name: String) {
        self.id = id
        self.name = name
    }
}

/// The text of a checkpoint QR code, signed by the station (the supervisor's Mac).
///
/// Format: `QRR1C.<payload>.<signature>`, both parts in Base64URL.
/// - payload: the checkpoint, as JSON
/// - signature: ECDSA P-256 over `"QRR1-CHECKPOINT\0" + payload`, made with the station's private key
///
/// Threat addressed (STRIDE, spoofing): a QR code printed by someone else, or by a fake Mac,
/// is refused because it does not carry a valid signature from our station.
public enum CheckpointCode {
    public static let prefix = "QRR1C."

    /// Label signed together with the payload ("domain separation"): a signature made for a
    /// checkpoint can't be reused as a signature for anything else in the project.
    static let domain = Data("QRR1-CHECKPOINT\u{0}".utf8)

    /// Real codes are a few hundred characters. Refusing huge input is cheap protection against abuse.
    static let maxLength = 2_000

    /// Station side: turns a checkpoint into signed QR code text.
    public static func make(for checkpoint: Checkpoint, signingKey: P256.Signing.PrivateKey) throws -> String {
        let payload = try JSONEncoder().encode(checkpoint)
        let signature = try signingKey.signature(for: domain + payload)
        return prefix + payload.base64URLEncodedString() + "." + signature.rawRepresentation.base64URLEncodedString()
    }

    /// Phone and station side: checks the signature first, and only then reads the checkpoint.
    public static func verify(_ code: String, stationKey: P256.Signing.PublicKey) throws -> Checkpoint {
        guard code.utf8.count <= maxLength, code.hasPrefix(prefix) else {
            throw CheckpointCodeError.notACheckpointCode
        }
        let parts = code.dropFirst(prefix.count).split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let payload = Data(base64URLEncoded: String(parts[0])),
              let signatureBytes = Data(base64URLEncoded: String(parts[1])) else {
            throw CheckpointCodeError.notACheckpointCode
        }
        guard let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureBytes),
              stationKey.isValidSignature(signature, for: domain + payload) else {
            throw CheckpointCodeError.invalidSignature
        }
        // Only now that the bytes are known to be authentic do we parse them.
        guard let checkpoint = try? JSONDecoder().decode(Checkpoint.self, from: payload) else {
            throw CheckpointCodeError.notACheckpointCode
        }
        return checkpoint
    }
}

public enum CheckpointCodeError: Error, Equatable {
    /// Not one of our QR codes (another app's code, random text, damaged code).
    case notACheckpointCode
    /// Right format, wrong signature: a fake or modified QR code.
    case invalidSignature
}
