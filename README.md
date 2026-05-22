# Wifi-Passport

Back up and restore your saved Windows WiFi profiles in a single encrypted file.

## Why

Windows stores WiFi passwords in a way tied to your user profile, so they vanish on reinstall or new user. The built-in `netsh` backup writes plaintext XML files to disk. Wifi-Passport gives you one encrypted file instead.

## Install

```
pip install -r requirements.txt
```

## Use

Back up every saved network. The file is written to `backup/wifi.passport` by default; pass an explicit path if you want it elsewhere.

```
python wifi_passport.py export wifi.passport
```

List what's in a backup without restoring:

```
python wifi_passport.py inspect wifi.passport
```

Check that a backup is healthy:

```
python wifi_passport.py verify wifi.passport
```

Restore (open PowerShell as Administrator first):

```
python wifi_passport.py import wifi.passport
```

## Passphrase

You pick a passphrase when you back up, and you need the same passphrase to restore. If you forget it, the file is unrecoverable — store it in a password manager.

The passphrase must be at least 14 characters and include at least 3 of: lowercase letters, uppercase letters, digits, symbols. Obvious choices like `Password1234567` are refused.

## Encryption

- **AES-256-GCM** for confidentiality and integrity.
- **Argon2id** for key derivation, with memory-hard defaults.
- Any tampering with the file (including the header) makes decryption fail.

## Requirements

- Windows. `export` reads profiles through the WLAN API (`wlanapi.dll`); `import` writes them back through `netsh`.
- Python 3.10 or newer.
- The three libraries in `requirements.txt`: `argon2-cffi`, `cryptography`, and `defusedxml`.
- `import` needs an elevated PowerShell.

## Tests

```
pytest test_wifi_passport.py
```

## License

MIT — see [LICENSE](LICENSE).
