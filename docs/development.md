# Development

How to build VaultGuard, run its tests, and change the parts that need care. For a map of
the codebase — targets, layers, `AppState`, the services — see
[architecture.md](architecture.md).

## Requirements

- macOS 14 or later, with a current Xcode
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) — `brew install xcodegen`
- Python 3 with the packages in `scripts/requirements.txt`, only if you regenerate test fixtures

The Xcode project is generated from `project.yml` and is not the source of truth. After pulling
changes that touch `project.yml`, regenerate it.

## Building

```
xcodegen generate
open VaultGuard.xcodeproj
```

The build needs no network access for its own dependencies. The Argon2 key-derivation code is
vendored in `Packages/Argon2`; there is no remote Swift package to resolve.

Local signed builds need an Apple team. Copy `Config/Signing.example.xcconfig` to
`Config/Signing.local.xcconfig` and set your team ID there.

## Tests

```
xcodegen generate
xcodebuild test -scheme VaultGuard -destination 'platform=macOS' -only-testing:VaultGuardTests
```

Or ⌘U in Xcode. The unit-test target is signed with no entitlements, so it runs without a team.

The same tests run in CI on every push and pull request — see
`.github/workflows/ci.yml`. The `hygiene` job there also checks localization key parity,
the vendored Argon2 hashes, that there are no remote Swift packages and no literal
localization keys, and a handful of project rules.

### What the tests cover

Most of the suite is ordinary unit tests. A few groups are worth knowing about:

- **Real container fixtures.** `KDBXReaderTests` (KeePassXC, AES + Argon2d),
  `KDBXv3Tests`, `KDBXv3AttachmentTests`, `KDBXv3KeyfileTests` and `KDBXv4ChaChaTests`
  (ChaCha20 + Argon2id + attachments) open real `.kdbx` files embedded as base64.
- **Acceptance tests for the KeePass write path.** `KeePassVaultAcceptanceTests` adds, edits,
  deletes, restores and moves entries through `KeePassBackend`, saves, reopens the file and
  checks what a user would see. Every round trip there is also a KDBX 3 → 4 conversion.
- **Key derivation.** `KeePassCryptoTests` checks Argon2d and Argon2id against vectors produced
  independently with `argon2-cffi`. A failure there means vault keys changed — see below.

### What the tests do not cover

`AppState` depends on the network client and the keychain, which the test target does not
build, so nothing in it is unit-tested directly. Logic that needs tests is moved out into a
type the target can build — `VaultListPipeline`, `RecentCiphersStore`, `KeePassBackupPolicy`,
`BitwardenEndpoints`, `AutoFillHostMatcher` are all examples. Follow the same pattern rather
than adding `AppState` to the test target: it would pull in most of the app.

There are no UI tests. An earlier attempt was removed; the behaviour it targeted is covered by
the acceptance tests above, without a signed runner, an accessibility grant or a sandboxed
fixture.

## Test fixtures

Fixtures are generated, not hand-edited. Each generator reproduces its fixture byte for byte,
so a fixture can always be traced back to how it was made.

```
pip install -r scripts/requirements.txt
python3 scripts/make-kdbx3-attachment-fixture.py            # KDBX 3.1 with an attachment
python3 scripts/make-kdbx3-attachment-fixture.py --keyfile  # KDBX 3.1 with a key file
python3 scripts/make-kdbx4-chacha-fixture.py                # KDBX 4, ChaCha20, Argon2id
```

Each prints the Swift literal to paste into its test, or writes the file with `--out`.

The KDBX 4 fixture is built from the format specification rather than with the app's own
writer. That is deliberate: a fixture made by the code under test only proves the code agrees
with itself.

## Changing the parts that need care

### Key derivation

Argon2 lives in `Packages/Argon2`, vendored at a pinned upstream commit. `PROVENANCE.md`
records which commit, which files and why; `SHA256SUMS` records the hash of each file, and CI
refuses a change to any of them. Updating it is a deliberate act:

1. Replace the files from a new pinned upstream commit.
2. Update the commit in `PROVENANCE.md` and regenerate `SHA256SUMS`.
3. Run the whole suite. `KeePassCryptoTests`, `CryptoServiceTests`, `KDBXReaderTests` and
   `KDBXv4ChaChaTests` must pass unchanged.

A change that alters key-derivation output locks every existing user out of their vault. There
is no migration path for that; the tests above are the only warning.

### Anything on the main actor that runs a KDF

The master-password KDF — PBKDF2 for Bitwarden, Argon2 or AES-KDF for KeePass — takes long
enough to freeze the window. It must never run on the main actor. Three places do it, and each
moves it off explicitly:

- Bitwarden login and reprompt — `AppState.deriveSession`, `verifyMasterPassword`
- opening a KeePass file — `AppState.loadFreshBackend`
- saving a KeePass file — `AppState.writeKeePassToDisk`, which also runs the KDF a second time
  to verify the written file

Relying on how Swift schedules a nonisolated async function is not enough: under a later Swift
mode those inherit the caller's actor. Use `Task.detached`, and say why in a comment.

### Key material and the crypto session

`CryptoService` is shared with work running off the main actor. It is kept safe by replacing
the instance rather than mutating it: `wipeCryptoSession` and `installCryptoSession` swap in a
new one, and a task already running keeps the instance it captured. Do not add code that
mutates the live instance from another thread.

## Export compliance

`docs/export-compliance.md` records the cryptography the app ships and the project's position
under U.S. export controls. Update it whenever the cryptographic inventory changes.
