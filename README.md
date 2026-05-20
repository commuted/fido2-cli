# FIDO2 CLI

A complete shell-based FIDO2/WebAuthn demo application for learning and testing FIDO2 authentication flows.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/commuted/fido2-cli/actions/workflows/test.yml/badge.svg)](https://github.com/commuted/fido2-cli/actions/workflows/test.yml)

## Features

- **Device Detection** - Automatic detection of connected FIDO2 authenticators
- **Registration** - Create credentials with multi-key support (backup keys)
- **Authentication** - Username-based authentication with any registered key
- **Passwordless Login** - Discoverable credentials for username-free authentication
- **Clone Detection** - Signature counter validation to detect cloned keys
- **PIN Management** - Set initial PIN and change existing PIN

## Requirements

- Python 3.9 or higher
- A FIDO2 compatible authenticator (YubiKey, SoloKey, etc.)
- Linux: `udev` rules for USB HID access (see below)

## Installation

### From PyPI (when published)

```bash
pip install fido2-cli
```

### From Source

```bash
git clone https://github.com/commuted/fido2-cli.git
cd fido2-cli
pip install -e .
```

### Development Installation

```bash
pip install -e ".[dev]"
```

## Linux USB Access

Try it, on Linux you may need udev rules to access FIDO2 devices without root. Create `/etc/udev/rules.d/70-fido2.rules`:

```
# FIDO2 devices
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0664", GROUP="plugdev", ATTRS{idVendor}=="1050"
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0664", GROUP="plugdev", ATTRS{idVendor}=="096e"
```

Then reload rules:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Ensure your user is in the `plugdev` group:

```bash
sudo usermod -aG plugdev $USER
```

Log out and back in for group changes to take effect.

## Usage

Run the demo:

```bash
fido2-demo
```

Or run directly:

```bash
python -m fido2_demo.cli
```

### Menu Options

```
===============================================
       FIDO2 DEMO APPLICATION
===============================================

  [1] Authenticate (with username)
  [2] Passwordless Login (discoverable)
  [3] Register (Create Account / Add Key)
  [4] List Registered Credentials
  [5] Delete Credential
  [6] Show Device Info
  [7] Set Initial PIN (new key)
  [8] Change PIN
  [9] Rescan for Devices
  [0] Exit
```

### Quick Start

1. **Insert your security key**
2. **Run `fido2-demo`**
3. **Register a new credential** (Option 3)
   - Enter a username and display name
   - Choose whether to make it a discoverable credential
   - Tap your key when prompted
4. **Authenticate** (Option 1 or 2)
   - For option 1: Enter your username, then tap
   - For option 2: Just tap (requires discoverable credential)

### Multi-Key Support

You can register multiple keys for the same user (backup keys):

1. Register your primary key
2. Select "Register" again with the same username
3. Confirm you want to add another key
4. Register your backup key

Any of your registered keys will work for authentication.

### Discoverable Credentials

Discoverable (resident) credentials are stored on the security key itself, enabling passwordless login:

- No need to enter username
- Requires PIN or biometric verification
- Uses limited storage on the key
- Can be managed with vendor tools (e.g., `ykman fido credentials list`)

## Security Features

### Signature Counter Validation

The application tracks signature counters to detect potentially cloned keys. If an authenticator returns a counter that doesn't increase from the stored value, a security warning is displayed.

### Clone Detection Warning

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  SECURITY WARNING: POSSIBLE CLONED KEY!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  Counter did not increase (stored: 10, received: 5)
  This may indicate the credential was cloned.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

## Development

### Running Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=src/fido2_demo --cov-report=html
```

### Project Structure

```
fido2-cli/
├── src/
│   └── fido2_demo/
│       ├── __init__.py
│       └── cli.py
├── tests/
│   └── test_cli.py
├── .github/
│   └── workflows/
│       └── test.yml
├── pyproject.toml
├── README.md
└── LICENSE
```

## Configuration

The demo uses `localhost` as the Relying Party ID for local testing. Credentials are stored in `fido2_credentials.json` in the current directory.

For production use, you would need:
- A real domain as the RP ID
- HTTPS origin
- Secure credential storage (database)

## Troubleshooting

### "No FIDO2 device found"

- Check USB connection
- On Linux: Verify udev rules and group membership
- Try a different USB port
- Some keys need a moment after insertion

### "PIN_AUTH_BLOCKED"

Remove and reinsert the security key, then try again.

### "PIN_BLOCKED"

The key must be reset (factory reset), which erases all credentials. Use vendor tools like `ykman fido reset`.

### "CREDENTIAL_EXCLUDED"

You're trying to register a key that's already registered for this user. Each physical key can only be registered once per user.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

Built with [python-fido2](https://github.com/Yubico/python-fido2) by Yubico.
