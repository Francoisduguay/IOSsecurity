# Prompt log

One entry per AI session: what we asked, what we kept, and who reviewed it.
Never paste secrets (keys, passwords, tokens) into an AI tool.

## 2026-11-23: project plan and teacher pitch

- Who:
- Tool: Claude (claude.ai)
- Asked: a step-by-step plan for the QR rounds project (J1 to J5), then an explanation
  of the project for the teacher, in English and French.
- Kept: the plan and the pitch text.
- Reviewed by:

## 2026-11-23: repository starter

- Who:
- Tool: Claude (claude.ai)
- Asked: a small starting point for the GitHub repository.
- Kept: README, team rules, PR template, J1/J2 templates, and the first feature in `Core/`
  (signed checkpoint QR codes, ECDSA P-256 with CryptoKit) with 5 unit tests.
- Reviewed by: (everyone must be able to explain `CheckpointCode.swift` before the defense)

## 2026-11-23: signed scan reports and replay protection

- Who:
- Tool: Claude Code
- Asked: signed scan reports (phone side), replay protection (timestamp, nonce, counter) and the
  station's scan verifier in `Core/`, with tests; then remove each check one at a time to prove a
  test fails; update J1, J2 and the README.
- Produced: `ScanReport.swift`, `ReplayGuard.swift`, `ScanVerifier.swift` and 19 new unit tests
  (24 in total), plus the doc updates. The tests were run on Linux, with swift-crypto (Apple's
  open-source version of the CryptoKit API) standing in for CryptoKit: run `swift test` on a Mac
  before merging.
- Reviewed by:
