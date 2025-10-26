## Introduction

The Password Strength Analyzer & Custom Wordlist Generator is a practical security tool designed for penetration testers, red-teamers, and students learning about password security. It combines automated password-strength assessment with targeted wordlist generation so you can both evaluate password resilience and produce realistic candidate lists for authorized password-auditing. The tool supports quick CLI workflows for headless use (ideal for Kali) and a lightweight Tkinter GUI for desktop testing.

## Features

Password strength assessment (uses zxcvbn when available; fallback entropy estimator otherwise).
Custom wordlist generation from seeds: name(s), pet(s), company, keywords, dates.
Mangling rules: case variants, limited leetspeak, appended years (full & two-digit), common symbols, permutations and separators (-, _).
Export to plain .txt (one candidate per line), ready for hashcat, john, etc.
CLI (argparse) and lightweight Tkinter GUI (for desktop Kali).
Safety caps and options to control output size.

## Installation (Kali Linux) — recommended

Run these commands in a terminal:

# (optional) system update
sudo apt update && sudo apt upgrade -y

# install system packages needed for Python + GUI
sudo apt install -y python3 python3-venv python3-pip python3-tk build-essential libssl-dev libffi-dev

# go to project folder (clone or copy repo)
cd ~/projects/passgen   # or wherever you placed the project

# create and activate virtualenv
python3 -m venv venv
source venv/bin/activate

# upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# download NLTK data used by the script
python -c "import nltk; nltk.download('punkt')"

## Generate a wordlist (example):
python passgen.py --name "Alice Example" --pet "Rex" --date "1995" -o alice_rex.txt --max 10000

## Assess a password with context:
python passgen.py --password "P@ssw0rd1995" --name "Alice Example" --company "Acme"

## Using generated lists with cracking tools
Examples:
# hashcat (adapt -m to your hash type)
hashcat -m 0 -a 0 hashes.txt alice_rex.txt

# john the ripper
john --wordlist=alice_rex.txt --rules myhashes.txt

## Summary
The analyzer evaluates individual passwords and returns a score, entropy estimate, and human-readable feedback where possible.
