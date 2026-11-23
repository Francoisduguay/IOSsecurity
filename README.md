# QR Rounds: anti-fraud patrol rounds

Security course project. During a patrol round, a guard's iPhone must prove the guard was
physically at each checkpoint. The guard scans a QR code signed by the supervisor's Mac,
confirms with Face ID, and the phone sends a signed report over an encrypted channel.
The Mac verifies everything and shows a live round log.

## Team

| Role | Name |
|---|---|
| Project lead | |
| Security architect | |
| iOS developer | |
| Red team (rotates each milestone) | |

## Repository layout

| Folder / file | Contents |
|---|---|
| `Core/` | Swift package with the security code shared by both apps, plus its unit tests |
| `docs/` | Milestone documents (J1 scope and STRIDE, J2 architecture) |
| `PROMPT_LOG.md` | Every AI prompt we used, and who reviewed the result |
| `Station-macOS/`, `Guard-iOS/` | The two apps (coming at J3) |

## Progress

- [x] Repository, team rules, prompt log
- [x] First security feature: signed checkpoint QR codes, with unit tests
- [ ] J1: scope and STRIDE table
- [ ] J2: architecture diagram and crypto choices
- [ ] J3: MVP running on the iPhone
- [ ] J4: cross-audit (OWASP MASVS)
- [ ] J5: defense

## Running the tests (on a Mac with Xcode)

```sh
cd Core
swift test
```

Expected result: `Executed 5 tests, with 0 failures`.

## Team rules

1. Every change goes through a pull request, reviewed and approved by another team member.
2. No secrets (keys, passwords, tokens) in Git or in AI tools.
3. Crypto and security code is never merged without a review and passing unit tests.
4. Every new dependency is checked before it is added. `Core` currently has none: only Apple's CryptoKit.
5. Every AI prompt is logged in `PROMPT_LOG.md`.
