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
| Tampering | Log modified in transit | | To do |
| Repudiation | "I never did that round" | | To do |
| Information disclosure | GPS positions in logs | | To do |
| Denial of service | Flood of fake scans | | To do |
| Elevation of privilege | Skipping Face ID | | To do |
