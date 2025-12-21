# 3Lock

Private notes & passwords. Local. Encrypted. Simple.

## Install

### macOS

Download [3Lock.dmg](https://github.com/kalba-lab/3lock/releases) → drag to Applications.

### From source

```bash
pip install -r requirements.txt
python -m threelock
```

**⚠️ macOS:** System Python has Tk 8.5 with rendering bugs. Use Homebrew Python:
```bash
brew install python@3.11
/opt/homebrew/bin/python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m threelock
python -m threelock --vault ~/my.3lock
python -m threelock --timeout 10
```

Default vault: `~/.3lock/vault.3lock`

## Security

- AES-256-GCM + Argon2id
- Clipboard auto-clear (30 sec)
- Session timeout
- No cloud, no sync, no tracking

**No password recovery.** Back up your vault.

## License

MIT, © [Kalba Lab](https://kalba.dev)

## Links

- [3lock.app](https://3lock.app)