# 3Lock

Private notes & passwords. Local. Encrypted. Simple.

## Philosophy

- One encrypted file, your data
- One password (+ YubiKey support coming)
- Works offline forever
- Code you can read in an evening

## Features

- AES-256-GCM encryption
- Argon2id key derivation (~1 sec per attempt)
- Hierarchical encryption (titles / content)
- Secure clipboard with auto-clear (30 sec)
- Session timeout (configurable)
- Cross-platform (macOS, Linux, Windows) — tested on macOS Silicon
- Minimal UI with tkinter (Python standard library, no extra dependencies)

## Installation

```bash
pip install -r requirements.txt
python -m threelock
```

## Usage

```bash
# Run with default vault location
python -m threelock

# Specify custom vault location
python -m threelock --vault ~/Documents/my.3lock

# Set session timeout (default: 5 minutes)
python -m threelock --timeout 10
```

## Data Location

By default, your encrypted vault is stored at:

```
~/.3lock/vault.3lock
```

This is a single JSON file containing all your encrypted data. Back it up!

## Security

- Titles encrypted with separate key from content
- Passwords never displayed, only copied to clipboard
- Clipboard auto-clears after 30 seconds
- Session timeout clears keys from memory
- Argon2id with ~1 sec derivation (brute-force resistant)
- Open source - audit it yourself

## Recovery

**If you forget your master password, there is no recovery.**

This is by design. Your data is encrypted locally and never leaves your device. Keep your master password safe!

## License

MIT

## Links

- Website: https://3lock.app
- GitHub: https://github.com/kalba-lab/3lock