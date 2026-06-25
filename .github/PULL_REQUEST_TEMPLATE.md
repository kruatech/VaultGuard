## Summary

<!-- What does this PR change and why? -->

## Related issue

<!-- e.g. Fixes #123 -->

## Testing done

<!-- How did you verify this? Which scenarios / macOS version? -->

## Checklist

- [ ] `xcodegen generate` produces a building project; the app builds in Xcode 15+
- [ ] Tests pass (or I explained why not)
- [ ] No master password or plaintext secret is written to disk
- [ ] No new force-unwraps (`!`) on values that can be `nil`
- [ ] User-facing strings go through `L10n.*` and exist in **both** `en.lproj` and `ru.lproj`
- [ ] Uses the per-account model (`keychain.account(id)`, `VaultCache.forAccount(id)`)
- [ ] No secrets, `Config/Signing.local.xcconfig`, or `xcuserdata` committed
