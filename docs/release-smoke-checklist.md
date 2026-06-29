# Release smoke checklist — AutoFill / Keychain / Passkey security rework

Scope: this checklist covers ONLY the security rework done across the AutoFill TTL,
`AutoFillCache`, keychain access-group split, and passkey gating. It is not the full release
gate — it is the device-dependent verification that unit tests cannot cover (the keychain and
the shared App Group require real entitlements and a signed build).

Unit-testable parts (TTL payload validity, `AutoFillCache` seal/open + account/kind scope
isolation, `AutoFillRecord` codable) are covered by `VaultGuardTests/AutoFillSecurityTests.swift`
and should pass in CI:

```
xcodegen generate
xcodebuild test -scheme VaultGuard -destination 'platform=macOS'
```

Everything below must be run on a signed build on a real Mac, because it depends on the
keychain access groups, the shared App Group container, and Local Authentication.

## 0. Project generation and signing

- [ ] `xcodegen generate` succeeds.
- [ ] App target is entitled to BOTH keychain access groups: `…com.kruatech.vaultguard.private`
      and `…com.kruatech.vaultguard`.
- [ ] AutoFill extension target is entitled to ONLY the shared group `…com.kruatech.vaultguard`.
- [ ] `AutoFillCache.swift`, `CredentialProviderViewController+Passkey.swift`, `Fido2.swift`,
      and `PasskeyStore.swift` compile into the extension target.
- [ ] Provisioning / Apple ID includes both groups, so writing app-private items does not fail
      with a missing-entitlement error.

## 1. Server vault — login and AutoFill (TTL)

- [ ] Log in to a self-hosted Bitwarden/Vaultwarden-compatible server. Login succeeds, meaning
      tokens are written to the app-private keychain group without error.
- [ ] AutoFill in Safari offers credentials after unlock (served from `AutoFillCache`).
- [ ] Set the AutoFill TTL in Settings to 15 minutes. Wait past it without re-unlocking the app.
      AutoFill is now locked ("open VaultGuard"); it does not serve credentials.
- [ ] Re-unlock the app; AutoFill works again (a fresh secret + cache are published).

## 2. Local KDBX vault — open and AutoFill

- [ ] Open a local `.kdbx` database with the sample master password.
- [ ] AutoFill in Safari offers the KDBX logins after unlock.
- [ ] Closing the local vault (lock) makes AutoFill locked; the cache file is removed.

## 3. Revocation — every path clears AutoFill access

- [ ] Lock (sleep / screensaver / auto-lock) → AutoFill locked.
- [ ] Logout of the active account → AutoFill locked; account secrets wiped.
- [ ] Remove a (non-active) account from Settings → its AutoFill cache + shared key are gone.
- [ ] Switch accounts → the previous account's AutoFill state is not served.

## 4. Keychain isolation — the extension sees only the minimum

Verify from a small debug probe in the EXTENSION process (or via Keychain inspection on a dev
build) that the extension can read ONLY shared-group items and not app-private ones:

- [ ] Extension CAN read: shared vault key payload, active account id, vault kind, passkeys.
- [ ] Extension CANNOT read `accessToken`.
- [ ] Extension CANNOT read `refreshToken`.
- [ ] Extension CANNOT read `encryptedKey`.
- [ ] Extension CANNOT read `cacheKey`.

## 5. Legacy migration (upgrade from a pre-split build)

- [ ] Install a pre-split build, log in, then upgrade to this build.
- [ ] On first launch the migration runs once: the shared keychain group is wiped, so no legacy
      tokens/keys remain readable by the extension.
- [ ] The user is prompted to log in again; after unlock, AutoFill state is recreated.
- [ ] The migration does not run a second time (marker in the app-private group).

## 6. Passkeys — gating verification (BLOCKING decision point)

The passkey private keys are stored under a user-presence access control in the shared group.
The open question that only a device can answer: can the extension read that access-controlled
item AFTER the user authenticates?

- [ ] Create a passkey for a relying party in Safari. The user-presence prompt
      (Touch ID / device password) appears; the passkey is saved.
- [ ] Log in with that passkey (assertion). The user-presence prompt appears; **after a
      successful check, the assertion signature is produced and login succeeds.**

If the assertion FAILS after a successful Touch ID / password check (e.g. it returns
"credential not found" or a generic failure), the extension cannot read the access-controlled
item across processes. In that case STOP and choose one of:

- move passkey private keys to the Secure Enclave (sign without exporting the key; requires a
  software fallback for Intel Macs without a Secure Enclave), or
- accept user-presence enforced only at the flow level (the `PasskeyAuthView` prompt) and
  document the storage protection as a known limitation.

Do not silently fall back to an unauthenticated read.

Additional passkey checks:

- [ ] Logout / account removal / local vault removal deletes the passkey private keys
      (they must not remain readable afterwards).
- [ ] A passkey created under one account is not offered under a different account after a switch.
- [ ] A missing or corrupted credential produces a clear error state, not a crash or a debug
      message.
