# Door Lock Example

Demonstrates FIDO2 **implicit** authentication — the lowest assurance level, where
UP (User Present) and UV (User Verified) flags are not enforced. Intended for
physical access control scenarios (door locks, turnstiles, IoT devices) where
inserting a key or tapping a reader is sufficient proof of presence.

> **Note:** Standard CTAP2 authenticators (YubiKey, etc.) always assert UP=1 on
> any assertion. "Implicit" means this tool does not *require* that flag, making
> it compatible with hardware that supports a silent/ambient detection mode.

## Usage

```bash
# Register a key for a user
python door_lock.py register alice

# Unlock the door (performs real FIDO2 authentication)
python door_lock.py unlock alice

# List registered users
python door_lock.py list
```

Credentials are stored in `door_credentials.json` next to this script,
separate from your main `fido2-cli` credential store.

## Requirements

- A connected FIDO2 authenticator (YubiKey, SoloKey, etc.)
- `fido2-cli` installed (`pip install -e .` from the repo root) **or** run directly from the repo
- Linux: udev rules for USB HID access (see the main [README](../../README.md))
