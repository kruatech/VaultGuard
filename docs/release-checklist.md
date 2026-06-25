# Release checklist

Use this before making the repository public or submitting a build to App Store Connect.

## Repository hygiene

```bash
git ls-files | grep -E 'Signing\.local|xcuserdata|xcuserstate' && exit 1 || echo "ok: no local signing/user files tracked"
grep -RniE 'master password saved|password will be stored|save master password' VaultGuard && exit 1 || echo "ok: no misleading master-password persistence strings"
grep -RniE 'REPLACE_BEFORE_SUBMISSION|<DEMO_' docs/app-store-review-notes.md && echo "fill App Review demo credentials before App Store submission"
```

Do not publish archives that contain `Config/Signing.local.xcconfig`, `xcuserdata`, or user-state files even if git ignores them. `Config/Signing.xcconfig` and `Config/Signing.example.xcconfig` are safe to publish.

## Build and tests

```bash
# Optional for local signed builds. CI/test builds work without this file.
cp Config/Signing.example.xcconfig Config/Signing.local.xcconfig
# Edit Config/Signing.local.xcconfig and set your Apple Team ID.

xcodegen generate
xcodebuild test \
  -scheme VaultGuard \
  -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY=
```

Then run one signed Release build locally and verify:

- first login with Bitwarden cloud;
- first login with a Vaultwarden/self-signed test server;
- Touch ID unlock after quitting and reopening;
- lock/logout removes AutoFill access;
- attachment download, preview, and cleanup on lock;
- AutoFill provider can fill while unlocked and refuses while locked.

## App Store Connect

Before submitting:

- replace all `REPLACE_BEFORE_SUBMISSION_*` values in `docs/app-store-review-notes.md`;
- provide a temporary demo vault account with non-sensitive sample data;
- verify screenshots contain no real credentials, emails, tokens, or server secrets;
- complete App Privacy as **Data Not Collected** only if the binary still has no analytics, telemetry, tracking, ads, crash SDKs, or developer backend;
- answer export compliance based on the final binary and your jurisdiction;
- confirm both app and extension bundle IDs, App Group, Keychain group, sandbox, and AutoFill capabilities in the Apple Developer portal.
- confirm the Release/Archive build does **not** define `DEBUG_APPGROUP_FALLBACK` (it is Debug-only by design; an accidental define would let the encrypted cache fall back to the local sandbox instead of the shared App Group).

## Public release

- Tag the exact commit used for the App Store build.
- Keep `CHANGELOG.md` and App Store release notes aligned.
- If you publish a binary outside the App Store, notarize it separately.
