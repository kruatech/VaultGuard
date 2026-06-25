# Developer / debug builds

This document covers behavior that differs between Release and local debug builds.

## Strict App Group (shared cache)

The encrypted offline cache (`VaultCache`) and AutoFill rely on the App Group
container `group.com.kruatech.vaultguard`. Access is **strict**:

- If the App Group container is **not** provisioned/usable, `VaultCache` does
  **not** fall back to the local sandbox. The cache is simply not used, the
  AutoFill extension reports an unavailable/locked state, and the main app shows
  a configuration error on unlock.

### Opt-in sandbox fallback for development

If you want the old behavior locally (cache falls back to the app sandbox when
the group isn't set up — e.g. building without a paid team), compile with the
`DEBUG_APPGROUP_FALLBACK` flag. Add it to the **Debug** configuration only, e.g.
in `project.yml`:

```yaml
targets:
  VaultGuard:
    settings:
      configs:
        Debug:
          SWIFT_ACTIVE_COMPILATION_CONDITIONS: $(inherited) DEBUG_APPGROUP_FALLBACK
```

In that mode the fallback is taken and a fault is logged (`Log.fault`). The flag
is never defined in Release, so production builds stay strict.

## Code signing

`Config/Signing.xcconfig` is committed with safe blank defaults, so clean clones
and CI can run `xcodegen generate` without local signing files.
`Config/Signing.local.xcconfig` is git-ignored and holds your personal
`DEVELOPMENT_TEAM` only when you need signed local builds:

```bash
# Optional: only needed for locally signed builds.
cp Config/Signing.example.xcconfig Config/Signing.local.xcconfig
# Edit DEVELOPMENT_TEAM in Config/Signing.local.xcconfig.

xcodegen generate
```

CI builds with signing disabled (`CODE_SIGNING_ALLOWED=NO`) and therefore does
not exercise the AutoFill entitlements; verify AutoFill manually on a signed
build.

## Transport

When the scheme is omitted, VaultGuard normalizes the server URL to `https://` so
`vault.example.com` and `https://vault.example.com/` resolve to the same account
id/cache/keychain namespace. Explicit `http://` is preserved, but App Transport
Security still blocks arbitrary cleartext loads except local networking
(`NSAllowsLocalNetworking`). Self-signed certificates are never trusted silently;
the login screen exposes the self-signed option, then the SHA-256 fingerprint must
be confirmed once per host.
