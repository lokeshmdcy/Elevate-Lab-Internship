#!/usr/bin/env python3
"""
secure_store.py
AES-256-GCM file encrypt/decrypt CLI with encrypted metadata and SHA-256 integrity check.

Usage:
  python3 secure_store.py encrypt <input_file> <output_file.enc>
  python3 secure_store.py decrypt <input_file.enc> <output_file>

Dependencies:
  pip3 install cryptography
"""

import argparse
import json
import os
import struct
import sys
import getpass
import time
from hashlib import sha256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

MAGIC = b'AFSENCv1'  # 8 bytes
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERS = 200_000
KEY_LEN = 32  # 256-bit


def derive_key(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=default_backend()
    )
    return kdf.derive(passphrase)


def compute_sha256_bytes(b: bytes) -> str:
    return sha256(b).hexdigest()


def encrypt_file(in_path: str, out_path: str, passphrase: bytes):
    with open(in_path, 'rb') as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    # metadata
    meta = {
        "orig_name": os.path.basename(in_path),
        "timestamp": int(time.time()),
        "sha256": compute_sha256_bytes(plaintext),
        "size": len(plaintext)
    }
    meta_json = json.dumps(meta).encode('utf-8')

    # encrypt metadata with its own nonce
    meta_nonce = os.urandom(NONCE_SIZE)
    meta_ct = aesgcm.encrypt(meta_nonce, meta_json, None)  # associated data None

    # encrypt file body with separate nonce
    file_nonce = os.urandom(NONCE_SIZE)
    file_ct = aesgcm.encrypt(file_nonce, plaintext, None)

    # Write format:
    # MAGIC (8) | salt (16) | meta_nonce(12) | file_nonce(12) | meta_len(4 BE) | meta_ct | file_ct
    with open(out_path, 'wb') as out:
        out.write(MAGIC)
        out.write(salt)
        out.write(meta_nonce)
        out.write(file_nonce)
        out.write(struct.pack('>I', len(meta_ct)))
        out.write(meta_ct)
        out.write(file_ct)

    print(f"Encrypted '{in_path}' -> '{out_path}'")
    print(f"Original SHA256: {meta['sha256']}")
    print("Keep your passphrase safe. If you lose it, file cannot be recovered.")


def decrypt_file(in_path: str, out_path: str, passphrase: bytes):
    with open(in_path, 'rb') as f:
        data = f.read()

    pos = 0
    if len(data) < len(MAGIC) + SALT_SIZE + NONCE_SIZE*2 + 4:
        raise ValueError("Input file too small or corrupt.")

    magic = data[pos:pos+len(MAGIC)]; pos += len(MAGIC)
    if magic != MAGIC:
        raise ValueError("File magic mismatch. Not a supported encrypted file.")
    salt = data[pos:pos+SALT_SIZE]; pos += SALT_SIZE
    meta_nonce = data[pos:pos+NONCE_SIZE]; pos += NONCE_SIZE
    file_nonce = data[pos:pos+NONCE_SIZE]; pos += NONCE_SIZE
    (meta_len,) = struct.unpack('>I', data[pos:pos+4]); pos += 4

    if pos + meta_len > len(data):
        raise ValueError("Metadata length inconsistent / file corrupt.")

    meta_ct = data[pos:pos+meta_len]; pos += meta_len
    file_ct = data[pos:]

    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        meta_json = aesgcm.decrypt(meta_nonce, meta_ct, None)
    except Exception as e:
        raise ValueError("Failed to decrypt metadata. Wrong passphrase or tampered file.") from e

    try:
        meta = json.loads(meta_json.decode('utf-8'))
    except Exception:
        raise ValueError("Metadata corrupt or unreadable.")

    # decrypt file content
    try:
        plaintext = aesgcm.decrypt(file_nonce, file_ct, None)
    except Exception as e:
        raise ValueError("Failed to decrypt file body. Wrong passphrase or tampered file.") from e

    # verify sha256
    actual_hash = compute_sha256_bytes(plaintext)
    expected_hash = meta.get("sha256")
    if expected_hash is None:
        raise ValueError("No SHA256 in metadata to verify integrity.")
    if not constant_time.bytes_eq(actual_hash.encode(), expected_hash.encode()):
        raise ValueError("Integrity check failed: SHA256 mismatch. File may be tampered or corrupted.")

    with open(out_path, 'wb') as out:
        out.write(plaintext)

    print(f"Decrypted -> '{out_path}'")
    print(f"Original filename: {meta.get('orig_name')}")
    print(f"Original timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta.get('timestamp', 0)))}")
    print(f"SHA256 verified: {actual_hash}")


def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM secure file store (CLI)")
    sub = parser.add_subparsers(dest='cmd')

    p_enc = sub.add_parser('encrypt', help='Encrypt a file')
    p_enc.add_argument('input', help='Input file path')
    p_enc.add_argument('output', help='Output .enc file path')

    p_dec = sub.add_parser('decrypt', help='Decrypt a .enc file')
    p_dec.add_argument('input', help='Input .enc file path')
    p_dec.add_argument('output', help='Output decrypted file path')

    args = parser.parse_args()
    if args.cmd not in ('encrypt', 'decrypt'):
        parser.print_help()
        sys.exit(1)

    # prompt passphrase (no echo)
    pw = getpass.getpass("Enter passphrase: ").encode('utf-8')
    pw2 = getpass.getpass("Confirm passphrase: ").encode('utf-8') if args.cmd == 'encrypt' else pw
    if args.cmd == 'encrypt' and pw != pw2:
        print("Passphrases do not match. Aborting.")
        sys.exit(2)

    try:
        if args.cmd == 'encrypt':
            encrypt_file(args.input, args.output, pw)
        else:
            decrypt_file(args.input, args.output, pw)
    except Exception as exc:
        print("Error:", exc)
        sys.exit(3)


if __name__ == '__main__':
    main()
