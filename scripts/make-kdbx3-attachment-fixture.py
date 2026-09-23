#!/usr/bin/env python3
"""Rebuild the KDBX 3.1 + attachment fixture used by VaultGuardTests.

The fixture is a base64 blob inside `VaultGuardTests/KDBXv3AttachmentTests.swift`. An opaque
blob nobody can regenerate is a liability, so this script reproduces it byte-for-byte from
the KDBX 3.1 container already embedded in `VaultGuardTests/KDBXv3Tests.swift`.

Why not pykeepass: `create_database` writes KDBX 4 only, and the point of this fixture is the
KDBX 3 layout — attachments as base64 in `<Meta><Binaries>` rather than in an inner-header
binary pool. So the existing v3 container is decrypted, its XML is edited, and it is
re-encrypted with the same header (same master seed, transform seed, rounds and IV). Nothing
about the container changes except the payload.

Requirements:
    pip install cryptography

Usage:
    python3 scripts/make-kdbx3-attachment-fixture.py            # print the Swift literal
    python3 scripts/make-kdbx3-attachment-fixture.py --out f.kdbx
"""
import argparse
import base64
import gzip
import hashlib
import os
import re
import struct
import sys
import textwrap

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("error: cryptography is required. Run: pip install cryptography", file=sys.stderr)
    sys.exit(1)

PASSWORD = b"v3pass"                      # the source fixture's password
# A 32-byte key file is used verbatim as the key-file component (KeePass rule: exactly 32 raw
# bytes are taken as-is, no hashing). Fixed bytes so the fixture stays reproducible.
KEYFILE = bytes(range(32))
ATTACHMENT_NAME = "note.txt"
ATTACHMENT_BYTES = b"VaultGuard KDBX3 attachment fixture\n"
SOURCE_TEST = "VaultGuardTests/KDBXv3Tests.swift"


def source_fixture(repo_root: str) -> bytes:
    """The KDBX 3.1 container embedded in KDBXv3Tests, as bytes."""
    path = os.path.join(repo_root, SOURCE_TEST)
    src = open(path, encoding="utf-8").read()
    m = re.search(r'private let fixtureB64 =\s*((?:\s*"[^"]*"\s*\+?)+)', src)
    if not m:
        print("error: could not find fixtureB64 in " + SOURCE_TEST, file=sys.stderr)
        sys.exit(1)
    return base64.b64decode("".join(re.findall(r'"([^"]*)"', m.group(1))))


def parse_header(data: bytes):
    """KDBX 3 header: 12-byte magic/version, then [id:1][size:2][value] until id == 0."""
    i, fields = 12, {}
    while True:
        fid = data[i]
        size = struct.unpack_from("<H", data, i + 1)[0]
        fields[fid] = data[i + 3:i + 3 + size]
        i += 3 + size
        if fid == 0:
            return fields, i


def composite_key(keyfile: bytes | None) -> bytes:
    """SHA256(SHA256(password) [+ keyfileKey]) — the order KDBXReader uses."""
    parts = hashlib.sha256(PASSWORD).digest()
    if keyfile is not None:
        parts += keyfile          # 32 raw bytes are the key-file component as-is
    return hashlib.sha256(parts).digest()


def master_key(fields, keyfile: bytes | None = None) -> bytes:
    """SHA256(masterSeed + AES-KDF(composite, transformSeed, rounds))."""
    composite = composite_key(keyfile)
    transform_seed, rounds = fields[5], struct.unpack("<Q", fields[6])[0]
    block = composite
    encryptor = Cipher(algorithms.AES(transform_seed), modes.ECB()).encryptor()
    for _ in range(rounds):
        block = encryptor.update(block)
    return hashlib.sha256(fields[4] + hashlib.sha256(block).digest()).digest()


def read_hashed_blocks(buf: bytes) -> bytes:
    """[index:4][sha256:32][size:4][data] repeated, terminated by a zero-size block."""
    out, p = bytearray(), 0
    while True:
        digest = buf[p + 4:p + 36]
        size = struct.unpack_from("<I", buf, p + 36)[0]
        p += 40
        if size == 0:
            return bytes(out)
        chunk = buf[p:p + size]
        p += size
        if hashlib.sha256(chunk).digest() != digest:
            raise ValueError("hashed block digest mismatch")
        out += chunk


def write_hashed_blocks(payload: bytes) -> bytes:
    out, index, p = bytearray(), 0, 0
    while p < len(payload):
        chunk = payload[p:p + 1024 * 1024]
        p += len(chunk)
        out += struct.pack("<I", index) + hashlib.sha256(chunk).digest()
        out += struct.pack("<I", len(chunk)) + chunk
        index += 1
    return bytes(out + struct.pack("<I", index) + b"\x00" * 32 + struct.pack("<I", 0))


def add_attachment(xml: str) -> str:
    """Add the binary to <Meta> and a reference to it from the first entry."""
    if "<Binaries" in xml:
        raise ValueError("source fixture already has a <Binaries> pool")
    payload = base64.b64encode(gzip.compress(ATTACHMENT_BYTES, mtime=0)).decode()
    xml = xml.replace(
        "</Meta>",
        '<Binaries><Binary ID="0" Compressed="True">%s</Binary></Binaries></Meta>' % payload, 1)
    # KeePass keeps <Binary> among an entry's children; inserting before <AutoType> puts it
    # after the <String> elements, which is where KeePassXC writes it.
    entry = xml.index("<Entry>")
    autotype = xml.index("<AutoType>", entry)
    ref = '<Binary><Key>%s</Key><Value Ref="0"/></Binary>' % ATTACHMENT_NAME
    return xml[:autotype] + ref + xml[autotype:]


# gzip stamps mtime into its header, so every run would otherwise produce different bytes
# for identical input. mtime=0 keeps the fixture reproducible: re-running this script must
# yield exactly the blob that is checked in.
def build(repo_root: str, keyfile: bytes | None = None) -> bytes:
    data = source_fixture(repo_root)
    fields, header_end = parse_header(data)
    header, key = data[:header_end], master_key(fields, keyfile)
    start_bytes, enc_iv = fields[9], fields[7]
    compressed = struct.unpack("<I", fields[3])[0] == 1

    # The source container has no key file; only the output gets one, so decryption uses the
    # password alone and re-encryption uses the composite that includes the key file.
    source_key = master_key(fields, None)
    decryptor = Cipher(algorithms.AES(source_key), modes.CBC(enc_iv)).decryptor()
    plain = decryptor.update(data[header_end:]) + decryptor.finalize()
    if plain[:32] != start_bytes:
        raise ValueError("StreamStartBytes mismatch — wrong password or KDF")

    payload = read_hashed_blocks(plain[32:])
    xml = gzip.decompress(payload).decode("utf-8") if compressed else payload.decode("utf-8")
    if keyfile is None:
        xml = add_attachment(xml)

    payload = gzip.compress(xml.encode("utf-8"), mtime=0) if compressed else xml.encode("utf-8")
    body = start_bytes + write_hashed_blocks(payload)
    pad = 16 - (len(body) % 16)                       # PKCS#7
    body += bytes([pad]) * pad
    encryptor = Cipher(algorithms.AES(key), modes.CBC(enc_iv)).encryptor()
    return header + encryptor.update(body) + encryptor.finalize()


def verify(blob: bytes, keyfile: bytes | None = None) -> None:
    """Re-open the result exactly the way KDBXReader does."""
    fields, header_end = parse_header(blob)
    key = master_key(fields, keyfile)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(fields[7])).decryptor()
    plain = decryptor.update(blob[header_end:]) + decryptor.finalize()
    assert plain[:32] == fields[9], "StreamStartBytes"
    xml = gzip.decompress(read_hashed_blocks(plain[32:])).decode("utf-8")
    if keyfile is None:
        assert "<Binaries>" in xml and 'Ref="0"' in xml, "attachment missing after round trip"
        print("ok: %d bytes, opens with the password, attachment present" % len(blob))
    else:
        print("ok: %d bytes, opens with password + key file" % len(blob))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", help="write the .kdbx here instead of printing a Swift literal")
    ap.add_argument("--repo-root", default=os.path.join(os.path.dirname(__file__), ".."),
                    help="repository root (defaults to the parent of scripts/)")
    ap.add_argument("--keyfile", action="store_true",
                    help="produce the KDBX 3 + key-file fixture instead (no attachment)")
    args = ap.parse_args()

    keyfile = KEYFILE if args.keyfile else None
    blob = build(os.path.abspath(args.repo_root), keyfile)
    verify(blob, keyfile)

    if args.out:
        open(args.out, "wb").write(blob)
        print("done: " + args.out)
        return
    lines = textwrap.wrap(base64.b64encode(blob).decode(), 100)
    print("\n    private let fixtureB64 =")
    print('        "' + '" +\n        "'.join(lines) + '"')


if __name__ == "__main__":
    main()
