#!/usr/bin/env python3
"""
FIDO2 CLI - Shell-based FIDO2/WebAuthn utility for testing and learning.

Supports interactive menu mode and non-interactive subcommands:
  fido2-cli register <username> [--discoverable] [--key-name NAME]
  fido2-cli auth <username>
  fido2-cli passwordless
  fido2-cli list
  fido2-cli delete <username> [--key-index N | --all]
  fido2-cli device
  fido2-cli pin set
  fido2-cli pin change
  fido2-cli            # interactive menu

Global options: --rp-id, --origin, --credentials, --min-level

┌─────────────────────────────────────────────────────────────────────┐
│  AUTHENTICATION LEVELS  (--min-level)                               │
│                                                                     │
│  implicit   No user action required. Key presence or ambient        │
│             detection alone is sufficient. Intended for physical    │
│             access control, door locks, and IoT devices where       │
│             inserting or tapping a reader acts as presence.         │
│             UP and UV flags are not enforced by this tool.          │
│             Note: standard CTAP2 authenticators always assert       │
│             UP=1; use with hardware that supports silent mode.      │
│                                                                     │
│  presence   Explicit tap or button press required (User Present).   │
│             Standard FIDO2 second-factor flow — no PIN needed.      │
│             Enforces UP=1 in the authenticator assertion.           │
│                                                                     │
│  verified   Tap + PIN or biometric required (User Verified).        │
│             Suitable for passwordless high-assurance flows and      │
│             single-factor passkey login. Enforces UP=1 + UV=1.     │
│                                                                     │
│  mfa        External password verified first, then FIDO2 with       │
│             user verification. Maximum assurance. Requires a        │
│             password hash stored at registration time.              │
│             Enforces password step + UP=1 + UV=1.                  │
└─────────────────────────────────────────────────────────────────────┘
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import secrets
from getpass import getpass
from importlib.metadata import version as _pkg_version
from pathlib import Path

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction, DefaultClientDataCollector
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AttestedCredentialData,
)

DEFAULT_RP_ID = "localhost"
DEFAULT_CREDENTIALS_FILE = Path.home() / ".config" / "fido2-cli" / "credentials.json"
PIN_MAX_ATTEMPTS = 3
MIN_LEVELS = ("implicit", "presence", "verified", "mfa")

# Module-level config — overridden at startup by main() from CLI args.
RP_ID = DEFAULT_RP_ID
RP_NAME = "FIDO2 CLI"
CREDENTIALS_FILE = DEFAULT_CREDENTIALS_FILE


class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\n" + "=" * 50)
        print("  >>> TAP YOUR SECURITY KEY NOW <<<")
        print("=" * 50 + "\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter your FIDO2 PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User verification required. Please verify on your device.")
        return True


def get_device():
    print("\nSearching for FIDO2 devices...")
    devices = list(CtapHidDevice.list_devices())

    if not devices:
        print("\nERROR: No FIDO2 device found!")
        print("Please insert your security key and try again.")
        return None

    if len(devices) == 1:
        print(f"Found device: {devices[0]}")
        return devices[0]

    print(f"\nFound {len(devices)} devices:")
    for i, dev in enumerate(devices):
        print(f"  [{i + 1}] {dev}")

    while True:
        try:
            choice = int(input("\nSelect device number: ")) - 1
            if 0 <= choice < len(devices):
                return devices[choice]
            print("Invalid selection.")
        except ValueError:
            print("Please enter a number.")


def load_credentials():
    if CREDENTIALS_FILE.exists():
        try:
            with open(CREDENTIALS_FILE, "r") as f:
                data = json.load(f)
                for username, user_data in data.items():
                    user_data["user_id"] = bytes.fromhex(user_data["user_id"])
                    for cred in user_data["credentials"]:
                        cred["attested_credential_data"] = AttestedCredentialData(
                            bytes.fromhex(cred["attested_credential_data"])
                        )
                        if "is_resident" not in cred:
                            cred["is_resident"] = False
                        if "counter" not in cred:
                            cred["counter"] = 0
                return data
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"Warning: Could not load credentials file: {e}")
            print("Starting with empty credentials.")
            return {}
    return {}


def save_credentials(credentials):
    CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    for username, user_data in credentials.items():
        data[username] = {
            "user_id": user_data["user_id"].hex(),
            "display_name": user_data.get("display_name", username),
            "credentials": [
                {
                    "attested_credential_data": bytes(cred["attested_credential_data"]).hex(),
                    "key_name": cred["key_name"],
                    "is_resident": cred.get("is_resident", False),
                    "counter": cred.get("counter", 0),
                }
                for cred in user_data["credentials"]
            ],
        }
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def check_resident_key_support(device):
    try:
        from fido2.ctap2 import Ctap2
        ctap2 = Ctap2(device)
        options = ctap2.info.options or {}
        return options.get("rk", False)
    except Exception:
        return False


def _decode_credential_id(raw):
    """Decode a credential/user ID that may be raw bytes or base64url-encoded."""
    if isinstance(raw, bytes):
        return raw
    padded = raw + "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(padded)


def _warn_cloned_key(stored, received):
    print("\n" + "!" * 50)
    print("  SECURITY WARNING: POSSIBLE CLONED KEY!")
    print("!" * 50)
    print(f"  Counter did not increase (stored: {stored}, received: {received})")
    print("  This may indicate the credential was cloned.")
    print("!" * 50)


def _hash_password(password: str) -> str:
    """Hash a password with scrypt and a random salt.

    Returns a self-contained string: ``scrypt$<salt_hex>$<hash_hex>``.
    """
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"scrypt${salt.hex()}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Verify a plaintext password against a stored scrypt hash."""
    _, salt_hex, hash_hex = stored.split("$")
    dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=16384, r=8, p=1)
    return dk.hex() == hash_hex


def _check_min_level(auth_data, min_level: str) -> None:
    """Enforce the minimum authentication level against authenticator assertion flags.

    Inspects the UP (User Present, bit 0) and UV (User Verified, bit 2) flags
    returned in the authenticator data and raises ``ValueError`` if the response
    does not satisfy the configured minimum level.

    ┌──────────────┬────────┬────────┬──────────────────────────────────────┐
    │ min_level    │ UP=1   │ UV=1   │ Typical use case                     │
    ├──────────────┼────────┼────────┼──────────────────────────────────────┤
    │ implicit     │ —      │ —      │ Physical access, door locks, IoT     │
    │ presence     │ req.   │ —      │ FIDO2 second-factor (no PIN)         │
    │ verified     │ req.   │ req.   │ Passwordless / passkey               │
    │ mfa          │ req.   │ req.   │ Password + FIDO2 UV (enforced above) │
    └──────────────┴────────┴────────┴──────────────────────────────────────┘

    Args:
        auth_data: Authenticator data from the assertion response.
        min_level: One of ``implicit``, ``presence``, ``verified``, ``mfa``.

    Raises:
        ValueError: When the assertion flags do not meet the required level.
    """
    flags = auth_data.flags
    up = bool(flags & 0x01)  # User Present flag
    uv = bool(flags & 0x04)  # User Verified flag

    if min_level == "implicit":
        return
    if min_level == "presence":
        if not up:
            raise ValueError(
                "Level 'presence' requires user presence (UP flag not set). "
                "The key was not tapped."
            )
    if min_level in ("verified", "mfa"):
        if not up:
            raise ValueError(
                f"Level '{min_level}' requires user presence (UP flag not set)."
            )
        if not uv:
            raise ValueError(
                f"Level '{min_level}' requires user verification (UV flag not set). "
                "PIN or biometric was not used."
            )


def register_credential(client, server, device, *, username=None, display_name=None, key_name=None, discoverable=None, min_level="presence"):
    """Register a new credential.

    Pass username/display_name/key_name/discoverable for non-interactive use.
    Leave as None to prompt interactively.

    When ``min_level`` is ``mfa`` a password is prompted and stored as a
    scrypt hash in the credentials file. That hash is required at authentication
    time whenever ``--min-level mfa`` is passed.

    Args:
        min_level: Minimum authentication level this registration must support.
                   One of ``implicit``, ``presence``, ``verified``, ``mfa``.
                   Affects the UV requirement sent to the authenticator and,
                   for ``mfa``, whether a password hash is stored.
    """
    print("\n" + "-" * 50)
    print("CREDENTIAL REGISTRATION")
    print("-" * 50)

    non_interactive = username is not None
    credentials = load_credentials()

    if username is None:
        username = input("\nEnter username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    is_new_user = username not in credentials

    if is_new_user:
        user_id = secrets.token_bytes(32)
        if display_name is None:
            display_name = input("Enter display name (or press Enter to use username): ").strip()
        if not display_name:
            display_name = username
        credentials[username] = {
            "user_id": user_id,
            "display_name": display_name,
            "credentials": [],
        }
        print(f"\nCreating new account for: {username}")
    else:
        user_id = credentials[username]["user_id"]
        display_name = credentials[username].get("display_name", username)
        existing_count = len(credentials[username]["credentials"])
        print(f"\nUser '{username}' already has {existing_count} key(s) registered.")
        if not non_interactive:
            if input("Add another key? (y/n): ").strip().lower() != "y":
                print("Registration cancelled.")
                return
        print(f"\nAdding backup key for: {username}")

    if key_name is None:
        key_name = input("Enter a name for this key (e.g., 'YubiKey 5', 'Backup'): ").strip()
    if not key_name:
        key_name = f"Key {len(credentials[username]['credentials']) + 1}"

    if discoverable is None:
        if check_resident_key_support(device):
            print("\nThis device supports discoverable credentials (resident keys).")
            print("Discoverable credentials allow passwordless login without typing username.")
            print("Note: Requires PIN/biometric and uses limited storage on the key.")
            discoverable = input("Make this a discoverable credential? (y/n): ").strip().lower() == "y"
        else:
            print("\nNote: This device does not support discoverable credentials.")
            discoverable = False
    elif discoverable and not check_resident_key_support(device):
        print("\nWarning: Device does not support discoverable credentials. Proceeding as non-discoverable.")
        discoverable = False

    user = PublicKeyCredentialUserEntity(
        id=user_id,
        name=username,
        display_name=display_name,
    )

    exclude_credentials = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=cred["attested_credential_data"].credential_id,
        )
        for cred in credentials[username]["credentials"]
    ]

    resident_key_req = ResidentKeyRequirement.REQUIRED if discoverable else ResidentKeyRequirement.DISCOURAGED
    user_verification = UserVerificationRequirement.REQUIRED if discoverable else UserVerificationRequirement.DISCOURAGED

    create_options, state = server.register_begin(
        user=user,
        credentials=exclude_credentials if exclude_credentials else None,
        resident_key_requirement=resident_key_req,
        user_verification=user_verification,
    )

    print("\nPlease wait for the prompt to tap your security key...")
    if discoverable:
        print("(You may need to enter your PIN)")

    # mfa: prompt for a password to store before touching the key
    if min_level == "mfa" and "password_hash" not in credentials[username]:
        print("\nMFA level requires a stored password for this user.")
        while True:
            password = getpass("Set MFA password (min 8 chars): ")
            if len(password) < 8:
                print("Password must be at least 8 characters. Try again.")
                continue
            if getpass("Confirm MFA password: ") != password:
                print("Passwords do not match. Try again.")
                continue
            break
        credentials[username]["password_hash"] = _hash_password(password)

    try:
        result = client.make_credential(create_options.public_key)
        auth_data = server.register_complete(state, result)
        cred_data = auth_data.credential_data
        credentials[username]["credentials"].append({
            "attested_credential_data": cred_data,
            "key_name": key_name,
            "is_resident": discoverable,
            "counter": 0,
        })
        save_credentials(credentials)

        print("\n" + "=" * 50)
        print("  REGISTRATION SUCCESSFUL!")
        print("=" * 50)
        print(f"  Username:    {username}")
        print(f"  Key Name:    {key_name}")
        print(f"  Discoverable: {'Yes' if discoverable else 'No'}")
        print(f"  Level:       {min_level}")
        print(f"  Total keys:  {len(credentials[username]['credentials'])}")
        print(f"  Credential:  {cred_data.credential_id.hex()[:32]}...")
        print("=" * 50)

    except Exception as e:
        if is_new_user and not credentials[username]["credentials"]:
            del credentials[username]
        print(f"\nRegistration failed: {e}")


def authenticate(client, server, *, username=None, min_level="presence"):
    """Authenticate with a registered credential.

    Pass ``username`` for non-interactive use; leave as ``None`` to prompt.

    The ``min_level`` controls what the authenticator must assert and, for
    ``mfa``, gates FIDO2 authentication behind a password check:

    - ``implicit``  — no flag enforcement (ambient/physical-presence use cases)
    - ``presence``  — UP=1 required (explicit tap, no PIN)
    - ``verified``  — UP=1 + UV=1 required (PIN or biometric)
    - ``mfa``       — password verified first, then UP=1 + UV=1 enforced

    Raises ``ValueError`` (caught internally) when the assertion flags do not
    satisfy the minimum level, and prints a rejection message to the user.

    Args:
        username:  Username to authenticate. Prompted if not provided.
        min_level: Minimum authentication level to enforce. One of
                   ``implicit``, ``presence``, ``verified``, ``mfa``.
    """
    print("\n" + "-" * 50)
    print("AUTHENTICATION (with username)")
    print("-" * 50)

    credentials = load_credentials()
    if not credentials:
        print("\nNo registered credentials found. Please register first.")
        return

    print("\nRegistered users:")
    for u, ud in credentials.items():
        key_count = len(ud["credentials"])
        print(f"  - {u} ({key_count} key{'s' if key_count != 1 else ''})")

    if username is None:
        username = input("\nEnter username to authenticate: ").strip()

    if username not in credentials:
        print(f"User '{username}' not found.")
        return

    user_data = credentials[username]
    user_creds = user_data["credentials"]

    # mfa: verify password before touching the key
    if min_level == "mfa":
        stored_hash = user_data.get("password_hash")
        if not stored_hash:
            print(
                f"\nUser '{username}' has no stored password. "
                "Re-register with --min-level mfa to set one."
            )
            return
        password = getpass("Enter MFA password: ")
        if not _verify_password(password, stored_hash):
            print("\nAuthentication rejected: incorrect password.")
            return
        print("Password verified. Proceeding with FIDO2 authentication...")

    uv = UserVerificationRequirement.REQUIRED if min_level in ("verified", "mfa") \
        else UserVerificationRequirement.DISCOURAGED

    allow_credentials = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=cred["attested_credential_data"].credential_id,
        )
        for cred in user_creds
    ]
    attested_credentials = [cred["attested_credential_data"] for cred in user_creds]

    request_options, state = server.authenticate_begin(
        credentials=allow_credentials,
        user_verification=uv,
    )

    print(f"\nAuthenticating as: {username}  [level: {min_level}]")
    if len(user_creds) > 1:
        print(f"(Any of your {len(user_creds)} registered keys will work)")
    print("Please wait for the prompt to tap your security key...")

    try:
        result = client.get_assertion(request_options.public_key)
        assertions = result.get_assertions()
        success = False
        last_error = None

        for idx, assertion in enumerate(assertions):
            used_cred_id = _decode_credential_id(assertion.credential["id"])

            used_key_name = "Unknown"
            used_cred = None
            for cred in user_creds:
                if cred["attested_credential_data"].credential_id == used_cred_id:
                    used_key_name = cred["key_name"]
                    used_cred = cred
                    break

            if not used_cred:
                continue

            new_counter = assertion.auth_data.counter
            stored_counter = used_cred.get("counter", 0)

            if new_counter != 0 and new_counter <= stored_counter:
                _warn_cloned_key(stored_counter, new_counter)
                return

            try:
                server.authenticate_complete(
                    state,
                    credentials=attested_credentials,
                    response=result.get_response(idx),
                )
                _check_min_level(assertion.auth_data, min_level)
                used_cred["counter"] = new_counter
                save_credentials(credentials)
                success = True
                print("\n" + "=" * 50)
                print("  AUTHENTICATION SUCCESSFUL!")
                print("=" * 50)
                print(f"  Welcome back, {username}!")
                print(f"  Authenticated with: {used_key_name}")
                print(f"  Level satisfied:    {min_level}")
                print("=" * 50)
                break
            except ValueError as e:
                print(f"\nAuthentication rejected: {e}")
                return
            except Exception as e:
                last_error = e
                continue

        if not success and last_error:
            print(f"\nAuthentication failed: {last_error}")

    except Exception as e:
        print(f"\nAuthentication failed: {e}")


def passwordless_authenticate(client, server, *, min_level="verified"):
    """Authenticate using discoverable credentials — no username required.

    Because no username is provided, the credential must be stored on the
    authenticator (discoverable / resident key). The minimum level defaults
    to ``verified`` because discoverable flows inherently require UV.

    The ``min_level`` controls what the authenticator must assert:

    - ``implicit``  — no flag enforcement (unusual for passwordless flows)
    - ``presence``  — UP=1 required (tap only; UV not enforced)
    - ``verified``  — UP=1 + UV=1 required (default; PIN or biometric)
    - ``mfa``       — UP=1 + UV=1 enforced (``mfa`` password step is not
                      applicable in passwordless flows; use ``verified`` for
                      the FIDO2 assertion and gate the overall flow externally)

    Args:
        min_level: Minimum authentication level to enforce. One of
                   ``implicit``, ``presence``, ``verified``, ``mfa``.
    """
    print("\n" + "-" * 50)
    print("PASSWORDLESS AUTHENTICATION")
    print("-" * 50)
    print("\nNo username required — just tap your key.")
    print("(If multiple accounts are on this key, it may show a picker)")

    credentials = load_credentials()
    user_id_to_data = {
        user_data["user_id"].hex(): {"username": username, "user_data": user_data}
        for username, user_data in credentials.items()
    }

    uv = UserVerificationRequirement.DISCOURAGED if min_level == "implicit" \
        else UserVerificationRequirement.REQUIRED

    request_options, state = server.authenticate_begin(
        credentials=None,
        user_verification=uv,
    )

    print("\nPlease tap your security key (PIN/biometric may be required)...")

    try:
        result = client.get_assertion(request_options.public_key)
        assertions = result.get_assertions()
        success = False
        last_error = None

        for idx, assertion in enumerate(assertions):
            user_handle = assertion.user.get("id") if assertion.user else None
            if not user_handle:
                continue

            user_id_hex = _decode_credential_id(user_handle).hex()
            if user_id_hex not in user_id_to_data:
                continue

            matched = user_id_to_data[user_id_hex]
            username = matched["username"]
            user_data = matched["user_data"]
            attested_credentials = [c["attested_credential_data"] for c in user_data["credentials"]]

            used_cred_id = _decode_credential_id(assertion.credential["id"])
            used_key_name = "Unknown"
            used_cred = None
            for cred in user_data["credentials"]:
                if cred["attested_credential_data"].credential_id == used_cred_id:
                    used_key_name = cred["key_name"]
                    used_cred = cred
                    break

            if used_cred:
                new_counter = assertion.auth_data.counter
                stored_counter = used_cred.get("counter", 0)
                if new_counter != 0 and new_counter <= stored_counter:
                    _warn_cloned_key(stored_counter, new_counter)
                    return

            try:
                server.authenticate_complete(
                    state,
                    credentials=attested_credentials,
                    response=result.get_response(idx),
                )
                _check_min_level(assertion.auth_data, min_level)
                if used_cred:
                    used_cred["counter"] = assertion.auth_data.counter
                    save_credentials(credentials)
                success = True
                print("\n" + "=" * 50)
                print("  PASSWORDLESS AUTH SUCCESSFUL!")
                print("=" * 50)
                print(f"  Welcome back, {username}!")
                print(f"  Authenticated with: {used_key_name}")
                print(f"  Level satisfied:    {min_level}")
                print("=" * 50)
                break
            except ValueError as e:
                print(f"\nAuthentication rejected: {e}")
                return
            except Exception as e:
                last_error = e
                continue

        if not success:
            if last_error:
                print(f"\nPasswordless authentication failed: {last_error}")
            else:
                print("\nNo valid credentials found on this key for this application.")
                print("Register a discoverable credential first.")

    except Exception as e:
        error_msg = str(e)
        if "No credentials" in error_msg or "CTAP" in error_msg:
            print("\nNo discoverable credentials found on this key.")
            print("Register a credential with --discoverable first.")
        else:
            print(f"\nPasswordless authentication failed: {e}")


def list_credentials():
    """List all registered credentials."""
    print("\n" + "-" * 50)
    print("REGISTERED CREDENTIALS")
    print("-" * 50)

    credentials = load_credentials()
    if not credentials:
        print("\nNo credentials registered yet.")
        return

    for username, user_data in credentials.items():
        key_count = len(user_data["credentials"])
        print(f"\n  User: {username}")
        print(f"  Display Name: {user_data.get('display_name', username)}")
        print(f"  User ID: {user_data['user_id'].hex()[:16]}...")
        print(f"  Registered Keys ({key_count}):")
        for i, cred in enumerate(user_data["credentials"], 1):
            attested = cred["attested_credential_data"]
            resident_status = "[Discoverable]" if cred.get("is_resident") else "[Server-side]"
            print(f"    [{i}] {cred['key_name']} {resident_status}")
            print(f"        Credential ID: {attested.credential_id.hex()[:24]}...")


def delete_credential(*, username=None, key_index=None, delete_all=False):
    """Delete a credential or user.

    Pass username + (key_index or delete_all=True) for non-interactive use.
    """
    print("\n" + "-" * 50)
    print("DELETE CREDENTIAL")
    print("-" * 50)

    credentials = load_credentials()
    if not credentials:
        print("\nNo credentials to delete.")
        return

    print("\nRegistered users:")
    for u, ud in credentials.items():
        key_count = len(ud["credentials"])
        print(f"  - {u} ({key_count} key{'s' if key_count != 1 else ''})")

    if username is None:
        username = input("\nEnter username: ").strip()

    if username not in credentials:
        print(f"User '{username}' not found.")
        return

    user_creds = credentials[username]["credentials"]

    # Non-interactive path
    if key_index is not None or delete_all:
        if delete_all:
            del credentials[username]
            save_credentials(credentials)
            print(f"\nUser '{username}' and all keys deleted.")
        else:
            idx = key_index - 1
            if not (0 <= idx < len(user_creds)):
                print(f"Invalid key index {key_index}. User has {len(user_creds)} key(s).")
                return
            key_name = user_creds[idx]["key_name"]
            is_resident = user_creds[idx].get("is_resident")
            del user_creds[idx]
            if not user_creds:
                del credentials[username]
                print(f"\nKey '{key_name}' deleted. No remaining keys — user removed.")
            else:
                save_credentials(credentials)
                print(f"\nKey '{key_name}' deleted. {len(user_creds)} key(s) remaining.")
            if is_resident:
                print("NOTE: The credential still exists on your security key.")
        return

    # Interactive path
    if len(user_creds) == 1:
        print(f"\nThis is the only key for '{username}'.")
        print("WARNING: Deleting it will remove the user entirely!")
        if user_creds[0].get("is_resident"):
            print("NOTE: This won't remove the credential from your security key.")
        if input("Delete user and their only key? (yes/no): ").strip().lower() == "yes":
            del credentials[username]
            save_credentials(credentials)
            print(f"\nUser '{username}' deleted.")
        else:
            print("Deletion cancelled.")
    else:
        print(f"\nKeys for '{username}':")
        for i, cred in enumerate(user_creds, 1):
            status = "[Discoverable]" if cred.get("is_resident") else "[Server-side]"
            print(f"  [{i}] {cred['key_name']} {status}")
        print("  [A] Delete ALL keys (remove user)")

        choice = input("\nSelect key to delete: ").strip()
        if choice.upper() == "A":
            confirm = input(f"Delete '{username}' and ALL {len(user_creds)} keys? (yes/no): ").strip().lower()
            if confirm == "yes":
                del credentials[username]
                save_credentials(credentials)
                print(f"\nUser '{username}' and all keys deleted.")
            else:
                print("Deletion cancelled.")
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(user_creds):
                    key_name = user_creds[idx]["key_name"]
                    is_resident = user_creds[idx].get("is_resident")
                    del user_creds[idx]
                    save_credentials(credentials)
                    print(f"\nKey '{key_name}' deleted. {len(user_creds)} key(s) remaining.")
                    if is_resident:
                        print("NOTE: The credential still exists on your security key.")
                else:
                    print("Invalid selection.")
            except ValueError:
                print("Invalid selection.")


def show_device_info(device):
    """Show information about the connected FIDO2 device."""
    print("\n" + "-" * 50)
    print("DEVICE INFORMATION")
    print("-" * 50)

    try:
        from fido2.ctap2 import Ctap2
        ctap2 = Ctap2(device)
        info = ctap2.info

        print(f"\n  Versions:    {', '.join(info.versions)}")
        print(f"  AAGUID:      {info.aaguid.hex()}")

        if info.extensions:
            print(f"  Extensions:  {', '.join(info.extensions)}")

        options = info.options or {}
        rk_support = options.get("rk", False)
        print(f"  Resident Key: {rk_support}")
        if rk_support:
            print("    (Supports discoverable/passwordless credentials)")
        print(f"  User Verification: {options.get('uv', False)}")

        if "clientPin" in options:
            pin_set = options.get("clientPin")
            if pin_set is True:
                print("  PIN Status:  Configured")
            elif pin_set is False:
                print("  PIN Status:  Supported but not set")
            else:
                print(f"  PIN Status:  {pin_set}")
        else:
            print("  PIN Status:  Not supported")

        if info.max_cred_count_in_list:
            print(f"  Max creds in list: {info.max_cred_count_in_list}")

    except Exception as e:
        print(f"\nCould not get device info: {e}")
        print("Device may only support CTAP1/U2F.")


def set_initial_pin(device):
    """Set the initial PIN on a security key that has no PIN yet."""
    print("\n" + "-" * 50)
    print("SET INITIAL PIN")
    print("-" * 50)

    try:
        from fido2.ctap2 import Ctap2
        from fido2.ctap2.pin import ClientPin

        ctap2 = Ctap2(device)
        options = ctap2.info.options or {}

        if "clientPin" not in options:
            print("\nThis device does not support PIN protection.")
            return
        if options.get("clientPin") is True:
            print("\nA PIN is already set. Use 'pin change' to change it.")
            return

        print("\nPIN requirements: minimum 4 characters, maximum 63 bytes (UTF-8).")

        while True:
            print()
            new_pin = getpass("Enter new PIN: ")
            if len(new_pin) < 4:
                print("PIN must be at least 4 characters. Try again.")
                continue
            if len(new_pin.encode("utf-8")) > 63:
                print("PIN is too long (max 63 bytes). Try again.")
                continue
            confirm_pin = getpass("Confirm new PIN: ")
            if new_pin != confirm_pin:
                print("PINs do not match. Try again.")
                continue
            break

        ClientPin(ctap2).set_pin(new_pin)
        print("\n" + "=" * 50)
        print("  PIN SET SUCCESSFULLY!")
        print("=" * 50)

    except Exception as e:
        print(f"\nFailed to set PIN: {e}")


def change_pin(device):
    """Change the PIN on a security key."""
    print("\n" + "-" * 50)
    print("CHANGE PIN")
    print("-" * 50)

    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin

    try:
        ctap2 = Ctap2(device)
        options = ctap2.info.options or {}
    except Exception as e:
        print(f"\nCould not connect to device: {e}")
        return

    if "clientPin" not in options:
        print("\nThis device does not support PIN protection.")
        return
    if options.get("clientPin") is not True:
        print("\nNo PIN is currently set. Use 'pin set' first.")
        return

    client_pin = ClientPin(ctap2)

    for attempt in range(PIN_MAX_ATTEMPTS):
        current_pin = getpass(f"Enter current PIN (attempt {attempt + 1}/{PIN_MAX_ATTEMPTS}): ")

        while True:
            print()
            new_pin = getpass("Enter new PIN: ")
            if len(new_pin) < 4:
                print("PIN must be at least 4 characters. Try again.")
                continue
            if len(new_pin.encode("utf-8")) > 63:
                print("PIN is too long (max 63 bytes). Try again.")
                continue
            if new_pin == current_pin:
                print("New PIN must differ from current PIN. Try again.")
                continue
            confirm_pin = getpass("Confirm new PIN: ")
            if new_pin != confirm_pin:
                print("PINs do not match. Try again.")
                continue
            break

        try:
            client_pin.change_pin(current_pin, new_pin)
            print("\n" + "=" * 50)
            print("  PIN CHANGED SUCCESSFULLY!")
            print("=" * 50)
            return
        except Exception as e:
            error_msg = str(e)
            if "PIN_INVALID" in error_msg:
                remaining = PIN_MAX_ATTEMPTS - attempt - 1
                if remaining > 0:
                    print(f"\nIncorrect PIN. {remaining} attempt(s) remaining.")
                else:
                    print("\nIncorrect PIN. No attempts remaining.")
            elif "PIN_AUTH_BLOCKED" in error_msg:
                print("\nPIN authentication blocked. Remove and reinsert key.")
                return
            elif "PIN_BLOCKED" in error_msg:
                print("\nPIN is blocked. Key must be reset (all data will be lost).")
                return
            else:
                print(f"\nFailed to change PIN: {e}")
                return

    print("\nToo many failed attempts. PIN change cancelled.")


def _interactive_menu():
    print("\n" + "=" * 50)
    print("       FIDO2 CLI")
    print("=" * 50)
    print("\n  [1] Authenticate (with username)")
    print("  [2] Passwordless Login (discoverable)")
    print("  [3] Register (Create Account / Add Key)")
    print("  [4] List Registered Credentials")
    print("  [5] Delete Credential")
    print("  [6] Show Device Info")
    print("  [7] Set Initial PIN (new key)")
    print("  [8] Change PIN")
    print("  [9] Rescan for Devices")
    print("  [0] Exit")
    print("\n" + "-" * 50)
    return input("Select option: ").strip()


def _build_parser():
    try:
        ver = _pkg_version("fido2-cli")
    except Exception:
        ver = "unknown"

    parser = argparse.ArgumentParser(
        prog="fido2-cli",
        description="FIDO2/WebAuthn CLI utility. Run without a subcommand for interactive mode.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {ver}")
    parser.add_argument(
        "--rp-id",
        default=DEFAULT_RP_ID,
        metavar="ID",
        help=f"Relying Party ID (default: {DEFAULT_RP_ID})",
    )
    parser.add_argument(
        "--origin",
        default=None,
        metavar="URL",
        help="Origin URL (default: https://<rp-id>)",
    )
    parser.add_argument(
        "--credentials",
        default=str(DEFAULT_CREDENTIALS_FILE),
        metavar="FILE",
        help=f"Credentials file path (default: {DEFAULT_CREDENTIALS_FILE})",
    )
    parser.add_argument(
        "--min-level",
        default="presence",
        choices=MIN_LEVELS,
        metavar="LEVEL",
        help=(
            "Minimum authentication level to enforce. "
            f"One of: {', '.join(MIN_LEVELS)}. "
            "implicit=no flags enforced; presence=UP required; "
            "verified=UP+UV required; mfa=password+UP+UV required. "
            "(default: presence)"
        ),
    )

    sub = parser.add_subparsers(dest="command")

    # register
    reg = sub.add_parser("register", help="Register a new credential")
    reg.add_argument("username", help="Username to register")
    reg.add_argument("--display-name", metavar="NAME", help="Display name (default: username)")
    reg.add_argument("--key-name", metavar="NAME", help="Name for this key (default: auto-generated)")
    reg.add_argument("--discoverable", action="store_true", default=False,
                     help="Create a discoverable (resident) credential")

    # auth
    auth_p = sub.add_parser("auth", help="Authenticate with username")
    auth_p.add_argument("username", help="Username to authenticate as")

    # passwordless
    sub.add_parser("passwordless", help="Passwordless authentication (no username needed)")

    # list
    sub.add_parser("list", help="List all registered credentials")

    # delete
    del_p = sub.add_parser("delete", help="Delete a credential or user")
    del_p.add_argument("username", help="Username")
    grp = del_p.add_mutually_exclusive_group()
    grp.add_argument("--key-index", type=int, metavar="N",
                     help="Delete key at position N (1-based); omit to choose interactively")
    grp.add_argument("--all", action="store_true", dest="delete_all",
                     help="Delete all keys for this user")

    # device
    sub.add_parser("device", help="Show FIDO2 device information")

    # pin
    pin_p = sub.add_parser("pin", help="PIN management")
    pin_sub = pin_p.add_subparsers(dest="pin_command")
    pin_sub.add_parser("set", help="Set initial PIN on a new key")
    pin_sub.add_parser("change", help="Change existing PIN")

    return parser


def main():
    global RP_ID, CREDENTIALS_FILE

    parser = _build_parser()
    args = parser.parse_args()

    RP_ID = args.rp_id
    CREDENTIALS_FILE = Path(args.credentials)
    origin = args.origin or f"https://{RP_ID}"
    min_level = args.min_level

    # Commands that don't need a physical device
    if args.command == "list":
        list_credentials()
        return

    if args.command == "delete":
        delete_credential(
            username=args.username,
            key_index=args.key_index,
            delete_all=args.delete_all,
        )
        return

    # All remaining commands need a device
    device = get_device()
    if not device:
        print("\nPlease connect a FIDO2 device and restart.")
        sys.exit(1)

    rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
    server = Fido2Server(rp)
    client_data_collector = DefaultClientDataCollector(origin)
    client = Fido2Client(device, client_data_collector, user_interaction=CliInteraction())

    if args.command == "register":
        register_credential(
            client, server, device,
            username=args.username,
            display_name=args.display_name,
            key_name=args.key_name,
            discoverable=args.discoverable if args.discoverable else None,
            min_level=min_level,
        )
    elif args.command == "auth":
        authenticate(client, server, username=args.username, min_level=min_level)
    elif args.command == "passwordless":
        passwordless_authenticate(client, server, min_level=min_level)
    elif args.command == "device":
        show_device_info(device)
    elif args.command == "pin":
        if args.pin_command == "set":
            set_initial_pin(device)
        elif args.pin_command == "change":
            change_pin(device)
        else:
            parser.parse_args(["pin", "--help"])
    else:
        # No subcommand — interactive menu mode
        print("\n" + "#" * 50)
        print("#" + " " * 48 + "#")
        print("#         FIDO2 CLI - Interactive Mode         #")
        print("#" + " " * 48 + "#")
        print("#" * 50)
        print(f"\n  RP ID:       {RP_ID}")
        print(f"  Credentials: {CREDENTIALS_FILE}")
        print(f"  Min level:   {min_level}")
        print("\n>>> Device ready. Waiting for your input...")

        while True:
            choice = _interactive_menu()
            if choice == "1":
                authenticate(client, server, min_level=min_level)
            elif choice == "2":
                passwordless_authenticate(client, server, min_level=min_level)
            elif choice == "3":
                register_credential(client, server, device, min_level=min_level)
            elif choice == "4":
                list_credentials()
            elif choice == "5":
                delete_credential()
            elif choice == "6":
                show_device_info(device)
            elif choice == "7":
                set_initial_pin(device)
            elif choice == "8":
                change_pin(device)
            elif choice == "9":
                new_device = get_device()
                if new_device:
                    device = new_device
                    client = Fido2Client(device, client_data_collector, user_interaction=CliInteraction())
                    print("Device updated successfully.")
            elif choice == "0":
                print("\nGoodbye!")
                break
            else:
                print("\nInvalid option. Please try again.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(0)
