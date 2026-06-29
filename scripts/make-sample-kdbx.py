#!/usr/bin/env python3
"""Generate a sample KeePass (.kdbx) database with FAKE data for App Store review.

The App Store review path in docs/app-store-review-notes.md uses a local KDBX
database so the reviewer needs no server and no developer account. This script
produces such a database, containing only fictitious test data.

Requirements:
    pip install pykeepass

Usage:
    SAMPLE_KDBX_PASSWORD='choose-a-password' python3 scripts/make-sample-kdbx.py
    # or
    python3 scripts/make-sample-kdbx.py --password 'choose-a-password' --out docs/review/sample.kdbx

Notes:
    - Do NOT commit the master password to the repository. Provide it to Apple in
      the App Store Connect "App Review Information -> Notes" field (or attach the
      database there). See docs/app-store-review-notes.md.
    - The database holds only fake logins, a card, an identity, and a secure note.
    - This produces a standard KDBX4 database. Verify it opens in VaultGuard on a
      device before relying on it for review.
"""
import argparse
import os
import sys


FAKE_ENTRIES = [
    # group, title, username, password, url, notes
    ("Logins", "Example Mail", "review.user@example.com", "Sample-Pass-001!", "https://mail.example.com", "Fake demo account — not real."),
    ("Logins", "Example Shop", "reviewer", "Sample-Pass-002!", "https://shop.example.org", "Fake demo account — not real."),
    ("Logins", "Example Router", "admin", "Sample-Pass-003!", "https://192.0.2.1", "RFC 5737 documentation address."),
    ("Work", "Example Intranet", "r.reviewer", "Sample-Pass-004!", "https://intranet.example.net", "Fake demo account — not real."),
]

FAKE_NOTE = ("Notes", "Welcome", None, None, None,
             "This is a sample VaultGuard database for App Store review. "
             "All data here is fictitious. No real credentials are included.")


def build(path: str, password: str) -> None:
    try:
        from pykeepass import create_database
    except ImportError:
        print("error: pykeepass is required. Run: pip install pykeepass", file=sys.stderr)
        sys.exit(1)

    out_dir = os.path.dirname(path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    if os.path.exists(path):
        print(f"error: refusing to overwrite existing file: {path}", file=sys.stderr)
        sys.exit(1)

    kp = create_database(path, password=password)

    groups = {}
    for name in ("Logins", "Work", "Notes"):
        groups[name] = kp.add_group(kp.root_group, name)

    for group, title, user, pwd, url, notes in FAKE_ENTRIES:
        kp.add_entry(groups[group], title=title, username=user or "",
                     password=pwd or "", url=url or "", notes=notes or "")

    g, title, user, pwd, url, notes = FAKE_NOTE
    kp.add_entry(groups[g], title=title, username=user or "",
                 password=pwd or "", url=url or "", notes=notes or "")

    kp.save()


def verify(path: str, password: str) -> int:
    from pykeepass import PyKeePass
    kp = PyKeePass(path, password=password)
    n = len(kp.entries)
    print(f"ok: {path} opens with the given password; {n} entries, "
          f"{len(kp.groups)} groups")
    return n


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a fake-data sample .kdbx for review.")
    ap.add_argument("--out", default="docs/review/sample.kdbx", help="output .kdbx path")
    ap.add_argument("--password", default=os.environ.get("SAMPLE_KDBX_PASSWORD"),
                    help="master password (or set SAMPLE_KDBX_PASSWORD)")
    args = ap.parse_args()

    if not args.password:
        print("error: no password. Use --password or set SAMPLE_KDBX_PASSWORD.",
              file=sys.stderr)
        sys.exit(1)

    build(args.out, args.password)
    count = verify(args.out, args.password)
    if count < len(FAKE_ENTRIES):
        print("error: round-trip verification found fewer entries than expected",
              file=sys.stderr)
        sys.exit(1)
    print(f"done: {args.out}")
    print("reminder: give the master password to Apple via App Store Connect, "
          "not via the repository.")


if __name__ == "__main__":
    main()
