# J2: architecture and crypto choices

## Diagram

To do: iPhone ↔ Mac diagram (pairing, then scans).

## Crypto choices

| Choice | Protects against | Why this choice | Status |
|---|---|---|---|
| Mac-signed checkpoint QR codes (ECDSA P-256) | Fake QR codes (spoofing) | Built into CryptoKit, no extra dependency; the phone only needs the Mac's public key | Done |
| Pairing by QR code, with a fingerprint check | | | To do |
| ECDH P-256 + HKDF → AES-GCM session keys | | | To do |
| Scan reports signed by the guard's phone (ECDSA P-256, `QRR1-SCAN` label) | Modified scans (tampering), "I never did that round" (repudiation) | Same algorithm as the QR codes. The station checks the exact bytes received and never re-encodes the JSON; the label stops a signature being reused for something else | Done in Core (`ScanReport.swift`, `ScanVerifier.swift`), with a software key for tests |
| Secure Enclave key signing each scan, unlocked by Face ID | | | To do |
| Nonce + timestamp + counter | Replay of a recorded scan | Timestamp: a recording only works for ±120 s. Nonce: the same scan can't be accepted twice in that window. Counter: old scans are refused for good, and gaps show scans that never arrived. One memory per phone | Done (`ReplayGuard.swift`) |
