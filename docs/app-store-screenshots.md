# Screenshots & visual assets

Two separate needs:

1. **README assets** in `docs/assets/` — referenced by `README.md`. The release-readiness
   CI job fails on a version tag if any are missing, so produce all of them before tagging.
2. **App Store screenshots** — uploaded in App Store Connect, not committed to the repo.

All images must use **only fictitious data** — no real accounts, emails, URLs, filesystem
paths, or personal information. The sample KeePass database from
`scripts/make-sample-kdbx.py` is a convenient source of fake content.

## README assets (exact filenames `README.md` expects)

Place each at `docs/assets/<name>`:

- `hero.png` — main window with a vault open and the item list visible (wide hero shot).
- `vault-type.png` — the vault-type chooser (local KeePass/KDBX vs self-hosted server).
- `keepass-unlock.png` — opening/unlocking a local `.kdbx` (file picker or password prompt).
- `item-detail.png` — a single login's detail view (use a fake entry).
- `password-generator.png` — the password generator with a template selected.
- `server-login.png` — the self-hosted server login screen (use a documentation host such
  as `https://vault.example.com`; do not show a real server).
- `settings.png` — Settings (e.g. the Security tab, showing the AutoFill key TTL control).
- `demo.gif` — a short loop: unlock → browse → copy → generator. Keep it small (≈720px wide).

Capture on a Retina display; PNG for stills. Crop to the window. After adding all eight,
the asset-link gate passes:

```bash
xcodegen generate   # only needed for the build steps of the job
# the README asset-link check just verifies the files exist
```

## App Store screenshots (App Store Connect, not the repo)

- Provide at least one screenshot for a required macOS size. Apple accepts macOS sizes of
  **1280×800, 1440×900, 2560×1600, or 2880×1800** (16:10). Use one size consistently.
- Recommended set (mirrors the README shots): item list, item detail, password generator,
  the vault-type chooser, and Settings.
- Show **both vault types** across the set (local KDBX and self-hosted server) so the
  listing reflects the standalone, multi-vault positioning.
- Fake data only. Avoid showing the macOS menu bar clock/notifications if it reveals
  anything identifying.

## Producing the sample database for the local review path

```bash
pip install pykeepass
SAMPLE_KDBX_PASSWORD='choose-a-strong-password' \
  python3 scripts/make-sample-kdbx.py --out docs/review/sample.kdbx
```

- Verify it opens in VaultGuard on a device.
- Provide the master password to Apple in App Store Connect (App Review Information →
  Notes), or attach the database there. Do **not** commit the password to the repository.
- `docs/review/` is a convenient location; either keep the generated `.kdbx` out of git or
  commit only the fake-data database (never the password). See `docs/app-store-review-notes.md`.
