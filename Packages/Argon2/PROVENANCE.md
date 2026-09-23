# Argon2 — vendored reference implementation

**Upstream:** https://github.com/P-H-C/phc-winner-argon2
**Commit:** `f57e61e19229e23c4445b85494dbf7c07de721cb`
**Licence:** CC0 1.0 or Apache License 2.0, at the user's option — see `LICENSE`, copied
verbatim. VaultGuard uses it under Apache 2.0.

## Why it is vendored

VaultGuard previously depended on `Argon2Swift`, a Swift wrapper, for one function. That
package declared this library as a SwiftPM dependency on the floating `master` branch **and**
carried it as a git submodule. The submodule is never compiled — the wrapper's target points
at a different directory — but SwiftPM clones it anyway, and that clone failed from a fresh
checkout, so the project did not build for anyone without a warm cache.

Vendoring removes the network from the key-derivation path entirely: the code that turns a
master password into a vault key is in this repository and changes only through its history.

## What is included

Exactly the files upstream's own `Package.swift` compiles at the commit above:

```
src/argon2.c  src/core.c  src/encoding.c  src/ref.c  src/thread.c  src/blake2/blake2b.c
```

plus the headers they include. `opt.c` is excluded, as upstream excludes it: it requires SSE
and does not build on Apple silicon. `bench.c`, `genkat.c`, `run.c` and `test.c` are
upstream's tools, not the library.

No file has been modified. The hash of every file is recorded in `SHA256SUMS`, and CI checks
it on every push and pull request (`.github/workflows/ci.yml`, job `hygiene`). To
check by hand:

```
cd Sources/CArgon2 && shasum -a 256 -c ../../SHA256SUMS
```

A mismatch means a file in the key-derivation path differs from the pinned upstream commit.
Treat it as a security issue, not a formatting one.

## How it was checked

Before the switch, the same six files were compiled with a standard C compiler and:

- upstream's own `test.c` passed in full — Argon2i and Argon2id, versions 0x10 and 0x13,
  error handling included;
- the two Argon2 vectors in `VaultGuardTests/KeePassCryptoTests.swift`, generated
  independently with `argon2-cffi`, matched byte for byte, called exactly the way
  `Argon2KDF` calls the library.

After it, the app's existing test suite — KeePass and Bitwarden key derivation, and the real
KDBX fixtures using Argon2d and Argon2id — is the regression check. Unchanged output there
means unchanged vault keys.

## Updating

Upstream has had no release since 20190702. If it ever changes, replace the files from a new
pinned commit, update the commit and the hashes above, and run the full test suite before
merging: a KDF change that alters output locks every existing user out of their vault.
