# Secure File Storage System with AES-256

A simple yet powerful **local file encryption and decryption system** built in Python using AES-256-GCM for confidentiality and integrity protection.

This project allows you to securely encrypt any file, store it as `.enc`, and later decrypt it using your passphrase — ensuring your data is safe from unauthorized access and tampering.

---

## Features

- **AES-256-GCM Encryption** — Strong, authenticated encryption for confidentiality and integrity.
- **PBKDF2 Key Derivation** — Password-based key stretching with unique salt per file.
- **Encrypted Metadata** — Original filename, timestamp, SHA-256 hash, and file size stored securely.
- **Integrity Verification** — Verifies SHA-256 hash to detect tampering or corruption.
- **Cross-Platform CLI** — Works on Linux, macOS, and Windows.
- **No plain-text key storage** — Passphrase-derived key only exists in memory.

---

## Tools & Libraries

- **Language:** Python 3
- **Library:** `cryptography`
- **OS tested:** Kali Linux

---

## Installation

Make sure you have Python 3 and `pip` installed.

```bash
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install cryptography


## Encrypt a File
python3 secure_store.py encrypt <input_file> <output_file.enc>

You’ll be asked to enter a passphrase (choose a strong one).
Keep it safe — without it, the file cannot be decrypted.

## Decrypt a File
python3 secure_store.py decrypt <input_file.enc> <output_file>

Enter the same passphrase used for encryption.
The script will verify file integrity automatically.


## Summary

This project is a Python-based tool that encrypts and decrypts files securely using AES-256 encryption.
It protects your data by converting files into unreadable .enc files that only you can unlock with your passphrase.
