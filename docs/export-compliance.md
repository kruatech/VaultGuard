# Export compliance

A factual record of the cryptography VaultGuard ships and the position the project takes on
U.S. encryption export controls. **This is not legal advice**, and nobody involved in writing
it is an export-control lawyer. It exists so that the question can be answered from evidence
rather than from memory — by a maintainer, by a lawyer being asked to confirm it, or by
someone forking the project who would otherwise have to work it out from scratch.

If you change what cryptography the app implements, or how it is distributed, this document
stops being true. See [What would break this position](#what-would-break-this-position).

## Distribution model

Every part of this matters to the conclusion below.

- **Free.** No purchase, no subscription, no paid tier.
- **Apache License 2.0.** See `LICENSE` and `NOTICE`.
- **Complete source published**, on GitHub, with no access restriction — no login, no fee, no
  approval step.
- **Binaries are built from that published source.** Nothing closed is compiled in, and no
  cryptographic code is fetched at build time: the Argon2 implementation is vendored in
  `Packages/Argon2` at a pinned upstream commit, with its provenance and file hashes recorded
  in `Packages/Argon2/PROVENANCE.md`.

## Cryptographic inventory

Everything the app implements or links, what it is used for, and the published specification
it follows.

| Primitive | Where | Purpose | Specification |
| --- | --- | --- | --- |
| AES-256-CBC | `Services/KeePass/KDBXReader.swift`, `KDBXWriter.swift` | KDBX container | FIPS 197 |
| AES-256-CBC + HMAC-SHA256 | `Services/CryptoService.swift` | Bitwarden `EncString` | FIPS 197, RFC 2104 |
| ChaCha20 | `Services/KeePass/KeePassStreamCiphers.swift` | KDBX 4 container and inner stream | RFC 8439 |
| Salsa20/20 | `Services/KeePass/KeePassStreamCiphers.swift` | KDBX 3.1 inner stream | published (Bernstein, 2005) |
| Argon2d / Argon2id | `Packages/Argon2` (vendored reference implementation), `Services/Argon2KDF.swift`, `Services/KeePass/KeePassKDF.swift` | KDBX 4 and Bitwarden key derivation | RFC 9106 |
| AES-KDF | `Services/KeePass/KeePassKDF.swift` | KDBX 3.1 key derivation | KDBX format specification |
| PBKDF2-HMAC-SHA256 | `Services/CryptoService.swift` (`CCKeyDerivationPBKDF`) | Bitwarden key derivation | RFC 8018 |
| HKDF-SHA256 | `Services/CryptoService.swift`, `Services/AutoFillCache.swift` | key stretching, AutoFill cache key | RFC 5869 |
| RSA-OAEP-SHA256 | `Services/CryptoService.swift` | organisation keys | PKCS #1 v2.2 |
| SHA-256 / SHA-512, HMAC | CryptoKit | hashing, integrity | FIPS 180-4, RFC 2104 |

Two places look bespoke at a glance and are not:

- `CryptoService` hashes the salt with SHA-256 before passing it to Argon2. That is
  Bitwarden's documented behaviour for its Argon2id KDF, not an invention of this project.
- `AutoFillCache.deriveKey` is plain HKDF-SHA256 with a salt and an info string. The info
  string binds the key to the account and vault kind; the construction is the RFC's.

**No unpublished cipher, KDF or protocol is implemented anywhere in the project.** Some of
these algorithms are implemented in Swift here rather than taken from the system — CryptoKit
offers no raw ChaCha20 or Salsa20 keystream, only AEAD — but a hand-written implementation of
a published algorithm is still the published algorithm.

## Position under the EAR

Stated as a chain, so that a reader can check each link rather than accept the conclusion.

1. **"Non-standard cryptography"** is defined in EAR §772.1 as an implementation involving
   proprietary or unpublished cryptographic functionality, including algorithms or protocols
   not adopted by a recognised standards body and not otherwise published. Every algorithm in
   the table above is published. The project therefore does not appear to provide non-standard
   cryptography.

2. **§742.15(b) notification.** The final rule of 29 March 2021 (86 FR 16482) narrowed the
   e-mail notification requirement for publicly available encryption source code so that it
   applies only to source code implementing non-standard cryptography. Given (1), no
   notification to BIS or the ENC Encryption Request Coordinator appears to be required.

3. **Publicly available source code.** EAR §734.3(b)(3) and §734.7 define what is publicly
   available. Source published on the internet without restriction, free of charge, qualifies.

4. **The compiled binary follows the source.** EAR §734.17 states that publicly available
   encryption source code *and corresponding object code* are not subject to the EAR when the
   source code meets the §742.15(b) requirements. The note to §734.3(b)(3) says the same.
   Because VaultGuard's binaries are built from the published source, they are that
   corresponding object code.

**Conclusion the project works from:** as a free, fully published, Apache-2.0 application
implementing only standard cryptography, VaultGuard and its binaries appear not to be subject
to the EAR. On that basis there is no ECCN to assign, no self-classification to perform, no
annual self-classification report, and no notification to send.

Note that this is a different and simpler route than mass-market classification. An analysis
that treats the app as a mass-market item under Note 3 to Category 5 Part 2 — reaching ECCN
5D992.c via License Exception ENC §740.17(b)(1) — is not wrong, but it is the path a *closed*
free application would have to take. Publication removes the need for it.

### One conflict in the sources

At least one commercial classification guide asserts that object code does **not** inherit the
publicly-available status and must be classified independently. The regulation text in
§734.17 and BIS's own guidance say otherwise. This document follows the regulation. It is the
single point where sources disagree, and therefore the one most worth confirming with a
specialist.

## What this does not cover

- **Apple's declaration.** `ITSAppUsesNonExemptEncryption` in `Resources/Info.plist` answers
  Apple's question, not the EAR's, and Apple asks it regardless of price or licence. Apple's
  own guidance requires a **French encryption declaration** for an app implementing
  industry-standard cryptography that is not provided by the operating system — but only where
  the app is distributed in France. Not being subject to the EAR does not affect this: it is
  French law. **This is the open question for App Store distribution.** Distribution of the
  `.dmg` directly does not raise it.
- **Sanctions.** OFAC administers country sanctions separately from the EAR. "Not subject to
  the EAR" says nothing about them.
- **Other jurisdictions.** This document addresses U.S. rules and flags the French one. It
  does not survey anywhere else.

## What would break this position

Each of these returns the project to a full classification question:

- **Any closed component.** BIS is explicit that an item is not publicly available merely
  because it incorporates publicly available open-source code. The position here rests on the
  whole application being published, not on its dependencies being open.
- **Charging for it**, or any restriction on obtaining the source or the binary.
- **Implementing a cipher, KDF or protocol that is not published** — including a "tweak" to a
  published one.
- **Shipping binaries that do not correspond to the published source.**

## Sources

- EAR §734.3, §734.7, §734.17 — scope, publicly available, encryption source and object code
- EAR §742.15(b) — notification for publicly available encryption source code
- EAR §772.1 — definition of "non-standard cryptography"
- EAR §740.17 and Note 3 to Category 5 Part 2 — the mass-market route, for the closed case
- 86 FR 16482 (29 March 2021) — the rule that narrowed §742.15(b) and §740.17(e)(3)
- Apple, *Complying with Encryption Export Regulations*, and App Store Connect's export
  compliance documentation reference

## Maintenance

Revisit this document when the cryptographic inventory changes, when the distribution model
changes, or when a release adds a country to the App Store availability list — particularly
France. Treat a change to `ITSAppUsesNonExemptEncryption` as a decision that belongs here
first and in `Info.plist` second: the key records a classification, it does not make one.
