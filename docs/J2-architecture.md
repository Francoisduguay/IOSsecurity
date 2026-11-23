# J2: architecture and crypto choices

## Diagram

To do: iPhone ↔ Mac diagram (pairing, then scans).

## Crypto choices

| Choice | Protects against | Why this choice | Status |
|---|---|---|---|
| Mac-signed checkpoint QR codes (ECDSA P-256) | Fake QR codes (spoofing) | Built into CryptoKit, no extra dependency; the phone only needs the Mac's public key | Done |
| Pairing by QR code, with a fingerprint check | | | To do |
| ECDH P-256 + HKDF → AES-GCM session keys | | | To do |
| Secure Enclave key signing each scan, unlocked by Face ID | | | To do |
| Nonce + timestamp + counter | | | To do |
