#!/usr/bin/env python3
"""Generate the KDBX 4 / ChaCha20 / Argon2id / attachments fixture for VaultGuardTests.

The suite's real-file coverage is lopsided: `KDBXReaderTests` uses a KeePassXC database with
AES-256-CBC and Argon2**d**, and `KDBXv3Tests` covers the 3.1 container. ChaCha20 as the outer
cipher, Argon2**id** as the KDF, and the inner-header binary pool are only exercised by writing
a file with `KDBXWriter` and reading it back — which proves the two agree with each other, not
that either agrees with the format.

So this builds the container independently, from the specification the reader implements:

    magic | version | header TLVs | SHA256(header) | HMAC(header) | HMAC'd blocks
    block           := HMAC-SHA256(blockKey(i), LE64(i) ‖ LE32(len) ‖ data) ‖ LE32(len) ‖ data
    blockKey(i)     := SHA512(LE64(i) ‖ SHA512(masterSeed ‖ transformed ‖ 0x01))
    masterKey       := SHA256(masterSeed ‖ transformed)
    transformed     := Argon2id(SHA256(SHA256(password)), salt, …)
    plaintext       := inner header ‖ XML          (gzip'd when compression = 1)

Requirements:
    pip install argon2-cffi cryptography

Usage:
    python3 scripts/make-kdbx4-chacha-fixture.py            # print the Swift literal
    python3 scripts/make-kdbx4-chacha-fixture.py --out f.kdbx
"""
import argparse
import base64
import gzip
import hashlib
import hmac
import struct
import sys
import textwrap

try:
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("error: needs argon2-cffi and cryptography. Run: pip install argon2-cffi cryptography",
          file=sys.stderr)
    sys.exit(1)

PASSWORD = b"chacha-pass"
ATTACHMENTS = [b"first attachment\n", b"second attachment payload\n"]

# Fixed inputs so the fixture is byte-for-byte reproducible. Real databases use random seeds;
# a test fixture that changed every run could not be checked in.
MASTER_SEED = bytes(range(0x10, 0x30))          # 32
NONCE = bytes(range(0x40, 0x4C))                # 12, ChaCha20 (RFC 8439)
ARGON_SALT = bytes(range(0x50, 0x70))           # 32
INNER_STREAM_KEY = bytes(range(0x80, 0xC0))     # 64, ChaCha20 inner stream

ARGON2ID_UUID = bytes([0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73,
                       0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6])
CHACHA20_UUID = bytes([0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5,
                       0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a])

# Deliberately tiny: the fixture is opened in unit tests, and real-world Argon2 parameters
# would add seconds to every run for no extra coverage.
ARGON_MEMORY_KIB = 1024
ARGON_ITERATIONS = 2
ARGON_PARALLELISM = 1

XML = """<KeePassFile><Meta><Generator>VaultGuard fixture</Generator>\
<DatabaseName>ChaCha</DatabaseName></Meta><Root><Group>\
<UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name>\
<Entry><UUID>BBBBBBBBBBBBBBBBBBBBBB==</UUID>\
<String><Key>Title</Key><Value>Example</Value></String>\
<String><Key>UserName</Key><Value>alice</Value></String>\
<Binary><Key>one.txt</Key><Value Ref="0"/></Binary>\
<Binary><Key>two.txt</Key><Value Ref="1"/></Binary>\
</Entry></Group></Root></KeePassFile>"""


def variant_dictionary() -> bytes:
    """KDF parameters as KeePass's VariantDictionary. `M` is in BYTES, not KiB."""
    out = struct.pack("<H", 0x0100)

    def entry(vtype: int, key: str, value: bytes) -> bytes:
        kb = key.encode()
        return (bytes([vtype]) + struct.pack("<I", len(kb)) + kb
                + struct.pack("<I", len(value)) + value)

    out += entry(0x42, "$UUID", ARGON2ID_UUID)
    out += entry(0x42, "S", ARGON_SALT)
    out += entry(0x05, "I", struct.pack("<Q", ARGON_ITERATIONS))
    out += entry(0x05, "M", struct.pack("<Q", ARGON_MEMORY_KIB * 1024))
    out += entry(0x04, "P", struct.pack("<I", ARGON_PARALLELISM))
    out += entry(0x04, "V", struct.pack("<I", 19))
    return out + b"\x00"


def header() -> bytes:
    def tlv(fid: int, data: bytes) -> bytes:
        return bytes([fid]) + struct.pack("<I", len(data)) + data

    out = struct.pack("<II", 0x9AA2D903, 0xB54BFB67)
    out += struct.pack("<HH", 1, 4)                      # minor, major
    out += tlv(2, CHACHA20_UUID)
    out += tlv(3, struct.pack("<I", 1))                  # gzip
    out += tlv(4, MASTER_SEED)
    out += tlv(7, NONCE)
    out += tlv(11, variant_dictionary())
    out += tlv(0, bytes([0x0d, 0x0a, 0x0d, 0x0a]))
    return out


def keys() -> tuple[bytes, bytes]:
    """(masterKey, hmacBase)."""
    composite = hashlib.sha256(hashlib.sha256(PASSWORD).digest()).digest()
    transformed = hash_secret_raw(
        secret=composite, salt=ARGON_SALT,
        time_cost=ARGON_ITERATIONS, memory_cost=ARGON_MEMORY_KIB,
        parallelism=ARGON_PARALLELISM, hash_len=32, type=Type.ID, version=19)
    master = hashlib.sha256(MASTER_SEED + transformed).digest()
    base = hashlib.sha512(MASTER_SEED + transformed + b"\x01").digest()
    return master, base


def block_key(index: int, base: bytes) -> bytes:
    return hashlib.sha512(struct.pack("<Q", index) + base).digest()


def inner_header() -> bytes:
    def item(tid: int, data: bytes) -> bytes:
        return bytes([tid]) + struct.pack("<I", len(data)) + data

    out = item(1, struct.pack("<I", 3))          # inner random stream: ChaCha20
    out += item(2, INNER_STREAM_KEY)
    for payload in ATTACHMENTS:
        # Inner-header binary item: [flags:1][data:N]. Flag 1 = protected in memory, which is
        # what KeePassXC writes for attachments.
        out += item(3, b"\x01" + payload)
    return out + item(0, b"")


def build() -> bytes:
    head = header()
    master, base = keys()

    payload = inner_header() + XML.encode("utf-8")
    payload = gzip.compress(payload, mtime=0)    # mtime=0 keeps the output reproducible

    encryptor = Cipher(algorithms.ChaCha20(master, b"\x00" * 4 + NONCE), mode=None).encryptor()
    ciphertext = encryptor.update(payload)

    out = head + hashlib.sha256(head).digest()
    out += hmac.new(block_key(0xFFFFFFFFFFFFFFFF, base), head, hashlib.sha256).digest()

    index, pos = 0, 0
    while pos < len(ciphertext):
        chunk = ciphertext[pos:pos + 1024 * 1024]
        pos += len(chunk)
        msg = struct.pack("<Q", index) + struct.pack("<I", len(chunk)) + chunk
        out += hmac.new(block_key(index, base), msg, hashlib.sha256).digest()
        out += struct.pack("<I", len(chunk)) + chunk
        index += 1
    terminator = struct.pack("<Q", index) + struct.pack("<I", 0)
    out += hmac.new(block_key(index, base), terminator, hashlib.sha256).digest()
    out += struct.pack("<I", 0)
    return out


def verify(blob: bytes) -> None:
    """Re-open the result the way KDBXReader does, step for step."""
    i, fields = 12, {}
    while True:
        fid = blob[i]
        size = struct.unpack_from("<I", blob, i + 1)[0]
        fields[fid] = blob[i + 5:i + 5 + size]
        i += 5 + size
        if fid == 0:
            break
    head = blob[:i]
    assert fields[2] == CHACHA20_UUID, "cipher is not ChaCha20"

    master, base = keys()
    assert blob[i:i + 32] == hashlib.sha256(head).digest(), "header SHA-256"
    expected = hmac.new(block_key(0xFFFFFFFFFFFFFFFF, base), head, hashlib.sha256).digest()
    assert blob[i + 32:i + 64] == expected, "header HMAC"

    p, index, ciphertext = i + 64, 0, b""
    while True:
        mac = blob[p:p + 32]
        size = struct.unpack_from("<I", blob, p + 32)[0]
        data = blob[p + 36:p + 36 + size]
        msg = struct.pack("<Q", index) + struct.pack("<I", size) + data
        assert hmac.new(block_key(index, base), msg, hashlib.sha256).digest() == mac, \
            "block %d HMAC" % index
        p += 36 + size
        if size == 0:
            break
        ciphertext += data
        index += 1

    decryptor = Cipher(algorithms.ChaCha20(master, b"\x00" * 4 + NONCE), mode=None).decryptor()
    plain = gzip.decompress(decryptor.update(ciphertext))

    c, binaries = 0, []
    while True:
        tid = plain[c]
        size = struct.unpack_from("<I", plain, c + 1)[0]
        data = plain[c + 5:c + 5 + size]
        c += 5 + size
        if tid == 0:
            break
        if tid == 3:
            binaries.append(data)
    assert [b[1:] for b in binaries] == ATTACHMENTS, "attachments did not survive"
    assert b"<KeePassFile>" in plain[c:], "XML missing"
    print("ok: %d bytes, ChaCha20 + Argon2id, %d attachments, opens with the fixture password"
          % (len(blob), len(binaries)))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", help="write the .kdbx here instead of printing a Swift literal")
    args = ap.parse_args()

    blob = build()
    verify(blob)

    if args.out:
        open(args.out, "wb").write(blob)
        print("done: " + args.out)
        return
    lines = textwrap.wrap(base64.b64encode(blob).decode(), 100)
    print('        "' + '" +\n        "'.join(lines) + '"')


if __name__ == "__main__":
    main()
