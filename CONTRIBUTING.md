# Contributing to VaultGuard

Thanks for your interest in improving VaultGuard — an independent, open-source macOS password manager for local KeePass (`.kdbx`) databases and self-hosted Bitwarden / Vaultwarden-compatible servers. Contributions of all kinds are welcome: bug reports, fixes, features, documentation, and translations.

## Before you start

- **Security issues are different.** Do **not** open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md) and report privately.
- For larger changes, open an issue first so we can agree on the approach before you invest time.
- By contributing you agree your contribution is licensed under the project's [Apache License 2.0](LICENSE).

## Development setup

Requirements: macOS 14+, Xcode 15+, [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`). A **paid** Apple Developer account is needed to build the AutoFill extension (App Group + AutoFill Credential Provider capability).

```bash
# 1. Provide your own signing config (git-ignored):
cp Config/Signing.example.xcconfig Config/Signing.local.xcconfig
#    then set DEVELOPMENT_TEAM (your Apple Team ID) in that file

# 2. Generate the Xcode project:
xcodegen generate

# 3. Open and build:
open VaultGuard.xcodeproj
```

There are no remote Swift packages to resolve: the Argon2 implementation is vendored in
`Packages/Argon2` (see its `PROVENANCE.md`). Changing it is a deliberate, reviewed update —
CI rejects any file that does not match `Packages/Argon2/SHA256SUMS`.

See **[docs/development.md](docs/development.md)** for running the tests, regenerating test
fixtures, and the rules for code that derives keys or runs off the main thread.

Never commit `Config/Signing.local.xcconfig` or any `xcuserdata` — they are git-ignored for a reason.

## Coding guidelines

- **No new force-unwraps** (`!`) on values that can realistically be `nil` (URLs, decoded data, optionals from external input). Use `guard let` with a typed error.
- **No secrets to disk.** The master password is never persisted; only derived/wrapped key material lives in the Keychain. Don't add code paths that store the master password.
- **Localize user-facing strings** via `L10n.*` and add the key to both `Resources/en.lproj/Localizable.strings` and `Resources/ru.lproj/Localizable.strings`. Keep the two files in parity. Never call `.localized` on a literal key string (`"misc.yes".localized`) — add a constant, so a typo in the key is a compile error rather than a raw key shown to the user.
- **Never run a key-derivation function on the main actor.** PBKDF2 and Argon2 take long enough to freeze the window. See `docs/development.md`.
- **Test logic by moving it out of `AppState`**, into a type the test target can build — not by adding `AppState` to the test target.
- **Per-account model only.** Use `keychain.account(id)` and `VaultCache.forAccount(id)`. There is no global/flat fallback.
- Keep the diff focused; match the surrounding style.

## Pull requests

1. Branch from `main`.
2. Make sure `xcodegen generate` still produces a building project and that tests pass.
3. Fill in the pull request template (testing done, checklist).
4. Reference any related issue.

## Reporting bugs / requesting features

Use the issue templates. Include your macOS version, app version, and whether you're using Bitwarden cloud or a self-hosted Vaultwarden server.
