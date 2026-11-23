# J1: scope and threat model (STRIDE)

## Goal

A guard must prove they were physically at each checkpoint of a round.

## In scope

- iPhone app (guard): scans checkpoint QR codes, asks for Face ID, sends signed scan reports
- Mac app (station): issues signed checkpoint QR codes, pairs phones, verifies scans, shows the round log
- The link between the iPhone and the Mac (local network)

## Out of scope

- To fill in (for example: cloud backend, Android, jailbroken phones)

## Assets to protect

- Integrity of the round log: who was where, and when
- The station's signing key and the guard's signing key
- The guards' GPS positions (privacy)

## STRIDE

| Threat | Example in our app | Mitigation | Status |
|---|---|---|---|
| Spoofing | Fake QR code, fake Mac | Checkpoint QR codes signed by the station (ECDSA P-256), verified by the phone and the station | Done: `Core/Sources/QRRoundsCore/CheckpointCode.swift` |
| Tampering | Scan report modified in transit; a recorded scan sent again (replay) | Each scan report is signed by the guard's phone (ECDSA P-256 over the exact bytes, with a `QRR1-SCAN` label): the station refuses any change. Replay protection: timestamp (±120 s), nonce and a per-phone counter, so a recorded scan can't be accepted twice | Signing and replay protection done in Core: `ScanReport.swift`, `ReplayGuard.swift`, `ScanVerifier.swift`. To do in the iOS app: key in the Secure Enclave, Face ID for each signature |
| Repudiation | "I never did that round" | Only the guard's phone can sign its scans (the station knows its public key from pairing), so a signed scan proves that phone made it. Face ID will tie the signature to the guard | Signing done in Core (`SoftwareSigner` is for tests and the Simulator only). To do in the iOS app: Secure Enclave key + Face ID for each signature |
| Information disclosure | GPS positions in logs | | To do |
| Denial of service | Flood of fake scans | | To do |
| Elevation of privilege | Skipping Face ID | | To do |
