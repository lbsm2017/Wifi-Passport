#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wifi-Passport - encrypted vault for Windows WiFi credentials.

Cryptographic construction
--------------------------
* Key derivation:   Argon2id (RFC 9106)
* Cipher:           AES-256-GCM
* AEAD pattern:     Full 45-byte header bound into associated data
                    so any header edit invalidates the GCM tag.
* RNG:              ``secrets.token_bytes`` (OS CSPRNG) per encryption,
                    for a fresh 128-bit salt and 96-bit nonce.

File format (v1)
----------------
::

    offset  size  field                     encoding
    ------  ----  ------------------------  -------------------------------
    0x00     8    MAGIC                     b"WIFIPASS"
    0x08     2    format_version            uint16, big-endian
    0x0A     1    kdf_id                    uint8 (1 = Argon2id)
    0x0B     1    argon2_time_cost          uint8
    0x0C     4    argon2_memory_kib         uint32, big-endian
    0x10     1    argon2_parallelism        uint8
    0x11    16    salt                      128-bit, CSPRNG
    0x21    12    nonce                     96-bit, CSPRNG
                                            -- end of AEAD AAD (45 B) --
    0x2D     N    ciphertext                AES-256-GCM output
    0x2D+N  16    gcm_tag                   authentication tag

Subcommands
-----------
::

    wifi-passport export    vault.passport   # snapshot every profile
    wifi-passport import    vault.passport   # restore (requires Admin)
    wifi-passport inspect   vault.passport   # decrypt + list
    wifi-passport verify    vault.passport   # decrypt + revalidate
    wifi-passport benchmark                  # time Argon2id

Author : lbsm2017
License: MIT
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import json
import math
import os
import platform
import re
import secrets
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Third-party dependencies - fail fast with actionable messages.
# ---------------------------------------------------------------------------
try:
    from argon2.low_level import Type as Argon2Type, hash_secret_raw
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: 'argon2-cffi' is required.\n"
        "Install with:  pip install argon2-cffi\n"
    )
    sys.exit(2)

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: 'cryptography' is required.\n"
        "Install with:  pip install cryptography\n"
    )
    sys.exit(2)

try:
    # defusedxml hardens xml.etree against Billion Laughs / entity-expansion /
    # external-entity attacks. We use it everywhere we parse XML, including
    # XML that has been authenticated by our AEAD: defence in depth lets us
    # safely open vaults received from third parties without trusting them.
    from defusedxml.ElementTree import fromstring as _xml_fromstring
    from defusedxml.ElementTree import ParseError as _XmlParseError
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: 'defusedxml' is required.\n"
        "Install with:  pip install defusedxml\n"
    )
    sys.exit(2)


__version__ = "1.0.0"


# ===========================================================================
# Constants and file format
# ===========================================================================

MAGIC: bytes = b"WIFIPASS"       # 8 bytes, ASCII identifier
FORMAT_VERSION: int = 1          # uint16, vault wire-format generation
PAYLOAD_VERSION: int = 1         # JSON inner schema version

KEY_BYTES: int = 32              # AES-256
SALT_BYTES: int = 16             # 128-bit salt (RFC 9106 recommended minimum)
NONCE_BYTES: int = 12            # 96-bit GCM nonce
GCM_TAG_BYTES: int = 16          # full 128-bit tag

# Header struct: MAGIC | version | kdf_id | t | m_kib | p | salt | nonce
# Sizes:           8  +    2    +   1    + 1 +   4   + 1 +  16  +  12  = 45
HEADER_STRUCT: str = ">8sHBBIB16s12s"
HEADER_SIZE: int = struct.calcsize(HEADER_STRUCT)
assert HEADER_SIZE == 45, "header layout drift"


class KdfId(IntEnum):
    """KDF identifiers stored in the vault header."""
    ARGON2ID = 1


# Argon2id parameter limits - refuse anything outside this envelope.
# The upper memory bound is deliberately tight (1 GiB) so a maliciously
# crafted vault can't trick a legitimate user into a multi-GiB allocation
# when they attempt to decrypt it. 1 GiB is already 4x the conservative
# default; no legitimate one-shot backup needs more.
ARGON2_TIME_MIN, ARGON2_TIME_MAX = 1, 32
ARGON2_MEM_KIB_MIN, ARGON2_MEM_KIB_MAX = 8 * 1024, 1024 * 1024  # 8 MiB .. 1 GiB
ARGON2_PARALLELISM_MIN, ARGON2_PARALLELISM_MAX = 1, 16

# Defaults: ~3x the OWASP 2024 minimum for high-value, low-frequency unlocks.
# A one-shot backup file deserves a robust KDF; ~1s on a modern desktop.
DEFAULT_ARGON2_TIME: int = 4
DEFAULT_ARGON2_MEMORY_KIB: int = 256 * 1024   # 256 MiB
DEFAULT_ARGON2_PARALLELISM: int = 2

MAX_VAULT_BYTES: int = 10 * 1024 * 1024       # 10 MiB sanity cap (input file)
# Defence in depth: cap plaintext too so a future bug producing a giant
# payload can't silently create an unloadable vault.
MAX_PLAINTEXT_BYTES: int = MAX_VAULT_BYTES - HEADER_SIZE - GCM_TAG_BYTES


# ===========================================================================
# Exceptions
# ===========================================================================

class VaultError(Exception):
    """Base class for all Wifi-Passport failures."""


class VaultFormatError(VaultError):
    """Vault file is malformed, truncated, or has unsupported parameters."""


class AuthenticationError(VaultError):
    """Decryption failed: wrong passphrase or tampered file."""


class PayloadError(VaultError):
    """Decrypted JSON payload failed schema validation."""


class PassphraseError(VaultError):
    """Passphrase rejected by the validator."""


class NetshError(VaultError):
    """A `netsh` invocation failed."""


# ===========================================================================
# Terminal styling (zero dependencies)
# ===========================================================================

def _supports_color() -> bool:
    """Return ``True`` if stdout looks like a color-capable terminal."""
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if platform.system() == "Windows":
        # Windows 10+ supports ANSI when ENABLE_VIRTUAL_TERMINAL_PROCESSING
        # (0x0004) is on. Read-modify-write the mode so we don't blast any
        # other bits the host had set (e.g. ENABLE_LVB_GRID_WORLDWIDE).
        try:
            kernel32 = ctypes.windll.kernel32
            stdout_handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            current_mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(stdout_handle, ctypes.byref(current_mode)):
                return False
            new_mode = current_mode.value | 0x0004
            if new_mode == current_mode.value:
                return True   # VT already enabled, nothing to write
            return bool(kernel32.SetConsoleMode(stdout_handle, new_mode))
        except Exception:
            return False
    return True


_COLOR_ENABLED: bool = _supports_color()


def _c(code: str, text: str) -> str:
    """Wrap ``text`` in ANSI escape ``code`` when color is enabled."""
    return f"\033[{code}m{text}\033[0m" if _COLOR_ENABLED else text


def info(msg: str) -> None:
    print(msg)


def success(msg: str) -> None:
    print(_c("32", "[ok] ") + msg)


def warn(msg: str) -> None:
    print(_c("33", "[!] ") + msg)


def fail(msg: str) -> None:
    print(_c("31", "[x] ") + msg, file=sys.stderr)


# ===========================================================================
# Passphrase validation
# ===========================================================================

MIN_PASSPHRASE_LEN: int = 14
MIN_ACCEPTABLE_SCORE: int = 70   # out of 100

COMMON_WEAK_TOKENS: frozenset[str] = frozenset({
    "password", "passw0rd", "qwerty", "asdfgh", "zxcvbn", "letmein",
    "welcome", "admin", "administrator", "iloveyou", "monkey", "dragon",
    "abc123", "trustno1", "qazwsx", "master", "login", "secret", "changeme",
    "default", "windows", "microsoft", "wifi", "wireless", "internet",
    "wifipassport", "passport", "vault", "backup",  # don't use the tool's own name
})

KEYBOARD_PATTERNS: tuple[str, ...] = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx", "1q2w3e4r",
    "qwerty", "asdfgh", "zxcvbn", "qazwsx",
    "abcdefghij", "0123456789",
)


@dataclass
class PassphraseAudit:
    """The verdict of :func:`validate_passphrase`.

    Attributes:
        score:        Integer 0-100 (higher is better).
        issues:       Showstoppers - passphrase is rejected if non-empty.
        warnings:     Soft observations that reduce the score but don't block.
        entropy_bits: Estimated effective entropy in bits.
    """
    score: int = 0
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    entropy_bits: float = 0.0

    @property
    def acceptable(self) -> bool:
        """``True`` iff the passphrase meets the minimum bar."""
        return self.score >= MIN_ACCEPTABLE_SCORE and not self.issues

    @property
    def label(self) -> str:
        """Human-readable strength tier."""
        s = self.score
        if s < 30:
            return "very weak"
        if s < 50:
            return "weak"
        if s < 70:
            return "fair"
        if s < 85:
            return "strong"
        return "excellent"


def _shannon_entropy_bits(text: str) -> float:
    """Return the Shannon entropy of ``text`` in bits."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    h_per_char = -sum((c / n) * math.log2(c / n) for c in freq.values())
    return h_per_char * n


def _charset_size(text: str) -> int:
    """Estimate the alphabet size used by ``text``."""
    size = 0
    if re.search(r"[a-z]", text):
        size += 26
    if re.search(r"[A-Z]", text):
        size += 26
    if re.search(r"\d", text):
        size += 10
    if re.search(r"[^\w\s]", text):
        size += 33
    if re.search(r"\s", text):
        size += 1
    return max(size, 1)


def _has_long_run(text: str, min_run: int = 4) -> bool:
    """Detect repeating or sequential runs (``aaaa``, ``1234``, ``dcba``)."""
    if len(text) < min_run:
        return False
    if re.search(rf"(.)\1{{{min_run - 1},}}", text):
        return True
    lowered = text.lower()
    for i in range(len(lowered) - min_run + 1):
        window = lowered[i : i + min_run]
        diffs = {ord(window[j + 1]) - ord(window[j]) for j in range(min_run - 1)}
        if diffs == {1} or diffs == {-1}:
            return True
    return False


def validate_passphrase(passphrase: str) -> PassphraseAudit:
    """Score a passphrase against multiple axes and return an audit."""
    audit = PassphraseAudit()
    score = 0.0

    # ---- Hard requirements ----------------------------------------------
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        audit.issues.append(
            f"Too short: {len(passphrase)} chars (minimum {MIN_PASSPHRASE_LEN})."
        )

    classes = {
        "lowercase": bool(re.search(r"[a-z]", passphrase)),
        "uppercase": bool(re.search(r"[A-Z]", passphrase)),
        "digit":     bool(re.search(r"\d", passphrase)),
        "symbol":    bool(re.search(r"[^\w\s]", passphrase)),
    }
    classes_present = sum(classes.values())
    if classes_present < 3:
        missing = [name for name, ok in classes.items() if not ok]
        audit.issues.append(
            "Need at least 3 of 4 character classes "
            f"(missing: {', '.join(missing)})."
        )

    if passphrase != passphrase.strip():
        audit.issues.append("Leading or trailing whitespace not allowed.")
    if not passphrase.isprintable():
        audit.issues.append("Contains non-printable characters.")

    # ---- Pattern detection ----------------------------------------------
    lowered = passphrase.lower()
    for token in COMMON_WEAK_TOKENS:
        if token in lowered:
            audit.issues.append(f"Contains a common weak token: '{token}'.")
            break

    for pattern in KEYBOARD_PATTERNS:
        if pattern in lowered or pattern[::-1] in lowered:
            audit.issues.append(f"Contains a keyboard pattern: '{pattern}'.")
            break

    if _has_long_run(passphrase):
        audit.warnings.append(
            "Contains a sequential or repeated run (e.g. 'aaaa', '1234')."
        )

    # ---- Entropy estimate ------------------------------------------------
    charset = _charset_size(passphrase)
    naive_bits = len(passphrase) * math.log2(charset)
    shannon_bits = _shannon_entropy_bits(passphrase)
    effective_bits = min(naive_bits, shannon_bits * 1.5)
    audit.entropy_bits = effective_bits

    # ---- Score synthesis -------------------------------------------------
    if len(passphrase) >= MIN_PASSPHRASE_LEN:
        length_score = min(40.0, (len(passphrase) - MIN_PASSPHRASE_LEN + 1) * 3.0)
        score += max(length_score, 5.0)
    score += classes_present * 5.0                   # 0..20
    score += min(30.0, effective_bits / 4.0)         # 0..30

    score -= 8 * len(audit.warnings)
    if audit.issues:
        score = min(score, 40.0)                     # cap hard-fail attempts

    audit.score = max(0, min(100, int(round(score))))
    return audit


# ===========================================================================
# Crypto core
# ===========================================================================

@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters embedded in the vault header."""
    time_cost: int = DEFAULT_ARGON2_TIME
    memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB
    parallelism: int = DEFAULT_ARGON2_PARALLELISM

    def validate(self) -> None:
        """Raise :class:`VaultFormatError` if parameters are out of range."""
        if not ARGON2_TIME_MIN <= self.time_cost <= ARGON2_TIME_MAX:
            raise VaultFormatError(f"argon2 time_cost out of range: {self.time_cost}")
        if not ARGON2_MEM_KIB_MIN <= self.memory_kib <= ARGON2_MEM_KIB_MAX:
            raise VaultFormatError(f"argon2 memory_kib out of range: {self.memory_kib}")
        if not ARGON2_PARALLELISM_MIN <= self.parallelism <= ARGON2_PARALLELISM_MAX:
            raise VaultFormatError(f"argon2 parallelism out of range: {self.parallelism}")

    def describe(self) -> str:
        """One-line human description for status output."""
        mib = self.memory_kib / 1024
        return (
            f"Argon2id  t={self.time_cost}  "
            f"m={mib:.0f} MiB  p={self.parallelism}"
        )


def derive_key(passphrase: str, salt: bytes, params: KdfParams) -> bytes:
    """Derive a 256-bit key from a passphrase using Argon2id."""
    if len(salt) != SALT_BYTES:
        raise VaultFormatError(f"salt must be {SALT_BYTES} bytes, got {len(salt)}")
    params.validate()
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=KEY_BYTES,
        type=Argon2Type.ID,
    )


def _pack_header(params: KdfParams, salt: bytes, nonce: bytes) -> bytes:
    """Serialize the fixed-size vault header."""
    return struct.pack(
        HEADER_STRUCT,
        MAGIC,
        FORMAT_VERSION,
        int(KdfId.ARGON2ID),
        params.time_cost,
        params.memory_kib,
        params.parallelism,
        salt,
        nonce,
    )


def _unpack_header(header: bytes) -> tuple[KdfParams, bytes, bytes]:
    """Parse a header, validating every field. Returns (params, salt, nonce)."""
    if len(header) != HEADER_SIZE:
        raise VaultFormatError(f"header must be {HEADER_SIZE} bytes")

    magic, version, kdf_id, t, m_kib, p, salt, nonce = struct.unpack(
        HEADER_STRUCT, header
    )
    if magic != MAGIC:
        raise VaultFormatError("not a Wifi-Passport vault (bad magic bytes)")
    if version != FORMAT_VERSION:
        raise VaultFormatError(
            f"unsupported vault version: {version} (expected {FORMAT_VERSION})"
        )
    if kdf_id != KdfId.ARGON2ID:
        raise VaultFormatError(f"unsupported KDF id: {kdf_id}")

    params = KdfParams(time_cost=t, memory_kib=m_kib, parallelism=p)
    params.validate()
    return params, salt, nonce


def encrypt_blob(
    plaintext: bytes,
    passphrase: str,
    params: KdfParams | None = None,
) -> bytes:
    """Encrypt ``plaintext`` into a complete vault byte string.

    The header is bound into AES-GCM's associated data, so any future
    modification of the KDF parameters, salt, or nonce will be detected
    on decryption.
    """
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise VaultFormatError(
            f"plaintext exceeds sanity limit "
            f"({len(plaintext)} > {MAX_PLAINTEXT_BYTES} bytes)"
        )
    params = params or KdfParams()
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = derive_key(passphrase, salt, params)
    header = _pack_header(params, salt, nonce)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=header)
    return header + ciphertext


def decrypt_blob(blob: bytes, passphrase: str) -> bytes:
    """Verify and decrypt a vault byte string."""
    if len(blob) < HEADER_SIZE + GCM_TAG_BYTES:
        raise VaultFormatError("file too small to be a valid vault")
    if len(blob) > MAX_VAULT_BYTES:
        raise VaultFormatError(f"file exceeds sanity limit ({MAX_VAULT_BYTES} bytes)")

    header = blob[:HEADER_SIZE]
    body = blob[HEADER_SIZE:]
    params, salt, nonce = _unpack_header(header)

    key = derive_key(passphrase, salt, params)
    try:
        return AESGCM(key).decrypt(nonce, body, associated_data=header)
    except InvalidTag as e:
        raise AuthenticationError(
            "Authentication failed: wrong passphrase, or the vault has been "
            "tampered with or corrupted."
        ) from e


# ===========================================================================
# Payload (JSON inside the encrypted blob)
# ===========================================================================

REQUIRED_PROFILE_FIELDS: tuple[str, ...] = ("ssid", "auth", "has_key", "xml")
REQUIRED_PAYLOAD_FIELDS: tuple[str, ...] = ("version", "host", "count", "profiles")


def _local_tag(tag: str) -> str:
    """Strip the XML namespace from a tag name."""
    return tag.split("}", 1)[-1]


def validate_profile_xml(xml_text: str) -> tuple[str, str, bool]:
    """Sanity-check a single Windows ``WLANProfile`` XML.

    Uses :mod:`defusedxml`, so Billion Laughs, quadratic blowup, external
    entity, and DTD-based attacks are rejected outright before the parser
    even begins to walk the tree.

    Returns:
        Tuple ``(ssid, authentication_type, has_keyMaterial)``.
    """
    try:
        root = _xml_fromstring(xml_text)
    except _XmlParseError as e:
        raise PayloadError(f"malformed XML: {e}") from e
    except Exception as e:
        # defusedxml raises EntitiesForbidden / DTDForbidden /
        # ExternalReferenceForbidden as ValueError subclasses.
        raise PayloadError(f"unsafe XML rejected: {e}") from e

    if _local_tag(root.tag) != "WLANProfile":
        raise PayloadError(f"not a WLANProfile root: {_local_tag(root.tag)}")

    ssid: str | None = None
    auth: str | None = None
    has_key = False
    for elem in root.iter():
        tag = _local_tag(elem.tag)
        if tag == "name" and ssid is None and elem.text:
            ssid = elem.text.strip()
        elif tag == "authentication" and auth is None and elem.text:
            auth = elem.text.strip()
        elif tag == "keyMaterial" and elem.text:
            has_key = True

    if not ssid:
        raise PayloadError("profile XML missing <name>")
    return ssid, auth or "unknown", has_key


def validate_payload(payload: Any) -> None:
    """Validate the decrypted JSON payload against the v1 schema."""
    if not isinstance(payload, dict):
        raise PayloadError("payload root must be a JSON object")

    for fld in REQUIRED_PAYLOAD_FIELDS:
        if fld not in payload:
            raise PayloadError(f"payload missing required field '{fld}'")

    if payload["version"] != PAYLOAD_VERSION:
        raise PayloadError(f"unsupported payload version: {payload['version']!r}")

    profiles = payload["profiles"]
    if not isinstance(profiles, list):
        raise PayloadError("'profiles' must be a list")

    if payload["count"] != len(profiles):
        raise PayloadError(
            f"count mismatch: header says {payload['count']}, "
            f"list has {len(profiles)}"
        )

    seen_ssids: set[str] = set()
    for index, profile in enumerate(profiles):
        if not isinstance(profile, dict):
            raise PayloadError(f"profile[{index}] is not an object")
        for fld in REQUIRED_PROFILE_FIELDS:
            if fld not in profile:
                raise PayloadError(f"profile[{index}] missing field '{fld}'")
        if not isinstance(profile["xml"], str):
            raise PayloadError(f"profile[{index}].xml must be a string")

        # Re-validate the inner XML - never trust the wrapper alone.
        ssid_in_xml, _, _ = validate_profile_xml(profile["xml"])
        if ssid_in_xml != profile["ssid"]:
            raise PayloadError(
                f"profile[{index}] SSID mismatch: wrapper says "
                f"{profile['ssid']!r}, XML says {ssid_in_xml!r}"
            )
        if profile["ssid"] in seen_ssids:
            raise PayloadError(f"duplicate SSID in payload: {profile['ssid']!r}")
        seen_ssids.add(profile["ssid"])


def build_payload(xml_texts: Iterable[str]) -> dict[str, Any]:
    """Bundle WLANProfile XML strings into a vault payload dictionary.

    Args:
        xml_texts: Iterable of raw ``<WLANProfile>`` XML strings, typically
            obtained from :func:`list_profile_xmls`. Each one is validated
            via :func:`validate_profile_xml` before being added.

    Returns:
        A dict ready to be JSON-encoded and encrypted.

    Raises:
        PayloadError: If any XML string is malformed.
    """
    profiles: list[dict[str, Any]] = []
    for text in xml_texts:
        ssid, auth, has_key = validate_profile_xml(text)
        profiles.append({
            "ssid": ssid,
            "auth": auth,
            "has_key": has_key,
            "xml": text,
        })
    payload = {
        "version": PAYLOAD_VERSION,
        "host": platform.node() or "unknown",
        "count": len(profiles),
        "profiles": profiles,
    }
    validate_payload(payload)   # self-check before encrypting
    return payload


# ===========================================================================
# Windows / netsh integration
# ===========================================================================

def require_windows() -> None:
    """Abort with a clear message if not running on Windows."""
    if platform.system() != "Windows":
        raise SystemExit("ERROR: this command must run on Windows (it uses netsh).")


def is_admin() -> bool:
    """Return ``True`` iff the current process has Administrator rights."""
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_netsh(args: list[str]) -> str:
    """Run ``netsh`` and return decoded stdout. Raises :class:`NetshError`."""
    try:
        result = subprocess.run(
            ["netsh", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as e:
        raise NetshError("netsh not found - is this Windows?") from e

    if result.returncode != 0:
        raise NetshError(
            f"netsh {' '.join(args)} exited {result.returncode}:\n"
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


# --- Windows WLAN API (replaces `netsh export profile` for reads) ----------
# We call wlanapi.dll directly via ctypes. This bypasses netsh's filename-
# based output, which silently drops every profile after the first SSID
# containing characters illegal in Windows filenames (`: ? * | < > / \ "`).
# WlanGetProfile returns the XML directly into memory, so no filesystem
# step is involved and no SSID gets mangled.

_WLAN_API_VERSION_2_0 = 0x00000002
_WLAN_PROFILE_GET_PLAINTEXT_KEY = 0x00000004
_ERROR_SUCCESS = 0
_WLAN_MAX_NAME_LENGTH = 256


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", _GUID),
        ("strInterfaceDescription", ctypes.c_wchar * _WLAN_MAX_NAME_LENGTH),
        ("isState", ctypes.c_int),
    ]


class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", ctypes.c_uint32),
        ("dwIndex", ctypes.c_uint32),
        ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1),  # flexible array
    ]


class _WLAN_PROFILE_INFO(ctypes.Structure):
    _fields_ = [
        ("strProfileName", ctypes.c_wchar * _WLAN_MAX_NAME_LENGTH),
        ("dwFlags", ctypes.c_uint32),
    ]


class _WLAN_PROFILE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", ctypes.c_uint32),
        ("dwIndex", ctypes.c_uint32),
        ("ProfileInfo", _WLAN_PROFILE_INFO * 1),  # flexible array
    ]


def _wlanapi() -> Any:
    """Load wlanapi.dll with proper argtypes/restypes (cached)."""
    if getattr(_wlanapi, "_cached", None) is not None:
        return _wlanapi._cached  # type: ignore[attr-defined]
    if platform.system() != "Windows":
        raise NetshError("WLAN API is Windows-only.")

    dll = ctypes.WinDLL("wlanapi.dll", use_last_error=True)

    dll.WlanOpenHandle.argtypes = [
        ctypes.c_uint32, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_void_p),
    ]
    dll.WlanOpenHandle.restype = ctypes.c_uint32

    dll.WlanCloseHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    dll.WlanCloseHandle.restype = ctypes.c_uint32

    dll.WlanEnumInterfaces.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)),
    ]
    dll.WlanEnumInterfaces.restype = ctypes.c_uint32

    dll.WlanGetProfileList.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(_GUID), ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_WLAN_PROFILE_INFO_LIST)),
    ]
    dll.WlanGetProfileList.restype = ctypes.c_uint32

    dll.WlanGetProfile.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(_GUID), ctypes.c_wchar_p,
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
    ]
    dll.WlanGetProfile.restype = ctypes.c_uint32

    dll.WlanFreeMemory.argtypes = [ctypes.c_void_p]
    dll.WlanFreeMemory.restype = None

    _wlanapi._cached = dll  # type: ignore[attr-defined]
    return dll


def list_profile_xmls() -> list[tuple[str, str]]:
    """Enumerate every WiFi profile and return ``[(ssid, profile_xml), ...]``.

    Uses ``wlanapi.dll`` directly. SSIDs with characters illegal in Windows
    filenames (``: ? * | < > / \\ "``) are handled correctly because nothing
    is written to disk - the XML comes back in memory. Plaintext
    ``<keyMaterial>`` is decrypted by DPAPI in the current user's context.
    """
    dll = _wlanapi()

    handle = ctypes.c_void_p()
    negotiated = ctypes.c_uint32()
    rc = dll.WlanOpenHandle(_WLAN_API_VERSION_2_0, None,
                            ctypes.byref(negotiated), ctypes.byref(handle))
    if rc != _ERROR_SUCCESS:
        raise NetshError(f"WlanOpenHandle failed (code {rc}).")

    try:
        guids = _enum_interface_guids(dll, handle)
        pairs: list[tuple[str, str]] = []
        seen: set[str] = set()
        for guid in guids:
            for ssid, xml in _profiles_for_interface(dll, handle, guid):
                if ssid in seen:
                    continue
                seen.add(ssid)
                pairs.append((ssid, xml))
        return pairs
    finally:
        dll.WlanCloseHandle(handle, None)


def _enum_interface_guids(dll: Any, handle: ctypes.c_void_p) -> list[_GUID]:
    """Snapshot every WLAN interface GUID. Frees the WLAN-allocated buffer."""
    ifaces_ptr = ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)()
    rc = dll.WlanEnumInterfaces(handle, None, ctypes.byref(ifaces_ptr))
    if rc != _ERROR_SUCCESS:
        raise NetshError(f"WlanEnumInterfaces failed (code {rc}).")
    try:
        ifaces = ifaces_ptr.contents
        arr = (_WLAN_INTERFACE_INFO * ifaces.dwNumberOfItems).from_address(
            ctypes.addressof(ifaces.InterfaceInfo)
        )
        # Deep-copy each GUID before freeing the source buffer.
        return [_copy_guid(arr[i].InterfaceGuid)
                for i in range(ifaces.dwNumberOfItems)]
    finally:
        dll.WlanFreeMemory(ifaces_ptr)


def _copy_guid(src: _GUID) -> _GUID:
    """Copy a GUID by value - the source memory may be freed momentarily."""
    dst = _GUID()
    ctypes.memmove(ctypes.byref(dst), ctypes.byref(src), ctypes.sizeof(_GUID))
    return dst


def _profiles_for_interface(
    dll: Any, handle: ctypes.c_void_p, guid: _GUID
) -> list[tuple[str, str]]:
    """List (ssid, profile_xml) for every profile on one interface."""
    list_ptr = ctypes.POINTER(_WLAN_PROFILE_INFO_LIST)()
    rc = dll.WlanGetProfileList(handle, ctypes.byref(guid), None,
                                ctypes.byref(list_ptr))
    if rc != _ERROR_SUCCESS:
        raise NetshError(f"WlanGetProfileList failed (code {rc}).")
    try:
        plist = list_ptr.contents
        items = (_WLAN_PROFILE_INFO * plist.dwNumberOfItems).from_address(
            ctypes.addressof(plist.ProfileInfo)
        )
        # Copy names out of WLAN-allocated memory.
        names = [str(items[i].strProfileName)
                 for i in range(plist.dwNumberOfItems)]
    finally:
        dll.WlanFreeMemory(list_ptr)

    return [(name, _get_profile_xml(dll, handle, guid, name)) for name in names]


def _get_profile_xml(
    dll: Any, handle: ctypes.c_void_p, guid: _GUID, profile_name: str
) -> str:
    """Return the plaintext-key profile XML for ``profile_name``."""
    xml_buf = ctypes.c_wchar_p()
    flags = ctypes.c_uint32(_WLAN_PROFILE_GET_PLAINTEXT_KEY)
    granted = ctypes.c_uint32(0)
    rc = dll.WlanGetProfile(
        handle, ctypes.byref(guid), ctypes.c_wchar_p(profile_name), None,
        ctypes.byref(xml_buf), ctypes.byref(flags), ctypes.byref(granted),
    )
    if rc != _ERROR_SUCCESS:
        raise NetshError(
            f"WlanGetProfile({profile_name!r}) failed (code {rc})."
        )
    try:
        return str(xml_buf.value or "")
    finally:
        # WlanFreeMemory expects the pointer value, not a c_wchar_p instance.
        dll.WlanFreeMemory(ctypes.cast(xml_buf, ctypes.c_void_p))


# --- netsh integration kept ONLY for the import path ----------------------
# `netsh wlan add profile filename=...` is what brings a profile back in.
# It's not affected by the filename-mangling problem (we control the
# filename we feed it), and there is no neat WlanSetProfile-based
# replacement worth the risk.

def import_profile_xml(xml_path: Path) -> None:
    """Install a single profile XML on this machine via ``netsh``."""
    _run_netsh([
        "wlan", "add", "profile",
        f"filename={xml_path}",
        "user=all",
    ])


def safe_xml_filename(index: int, ssid: str) -> str:
    """Build a collision-free XML filename for an SSID.

    The index prefix prevents two SSIDs that sanitize to the same string
    (e.g. ``"Wifi A"`` and ``"Wifi_A"``) from clobbering each other when
    written to a shared temp directory before ``netsh`` reads them.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", ssid) or "profile"
    return f"{index:03d}_{safe}.xml"


# ===========================================================================
# Atomic file I/O
# ===========================================================================

def atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically.

    Writes to a sibling ``.tmp`` file, ``fsync``s, then ``os.replace``
    (atomic on POSIX rename(2) and NTFS MoveFileEx with
    MOVEFILE_REPLACE_EXISTING).
    """
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")

    with open(tmp_path, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())

    os.replace(tmp_path, path)
    try:
        os.chmod(path, 0o600)    # best-effort permission tightening
    except OSError:
        pass


# ===========================================================================
# Passphrase prompting
# ===========================================================================

MAX_PASSPHRASE_ATTEMPTS: int = 5


def prompt_passphrase(*, confirm: bool) -> str:
    """Interactively ask for a passphrase, validating until acceptable.

    Args:
        confirm: When ``True``, also ask for a confirmation entry that
                 must match. Use this for ``export``.

    Raises:
        SystemExit: After :data:`MAX_PASSPHRASE_ATTEMPTS` failed attempts,
                    or if stdin is closed.
    """
    for _ in range(MAX_PASSPHRASE_ATTEMPTS):
        try:
            passphrase = getpass.getpass("Passphrase: ")
        except EOFError as e:
            raise SystemExit("ERROR: no passphrase available on stdin.") from e

        audit = validate_passphrase(passphrase)
        render_strength(audit)

        if not audit.acceptable:
            info("  -> Try a stronger passphrase.\n")
            continue

        if confirm:
            try:
                check = getpass.getpass("Confirm:    ")
            except EOFError as e:
                raise SystemExit("ERROR: no passphrase available on stdin.") from e
            if check != passphrase:
                fail("Passphrases don't match. Try again.\n")
                continue

        return passphrase

    raise SystemExit(
        f"ERROR: gave up after {MAX_PASSPHRASE_ATTEMPTS} failed passphrase attempts."
    )


def render_strength(audit: PassphraseAudit) -> None:
    """Print a colored strength bar and any warnings/issues."""
    filled = audit.score // 5
    bar = "#" * filled + "-" * (20 - filled)
    color = "31" if audit.score < 50 else "33" if audit.score < 70 else "32"
    info(
        f"  Strength: [{_c(color, bar)}] "
        f"{audit.score}/100  ({audit.label}, ~{audit.entropy_bits:.0f} bits)"
    )
    for warning in audit.warnings:
        warn(f"  {warning}")
    for issue in audit.issues:
        fail(f"  {issue}")


# ===========================================================================
# Subcommands
# ===========================================================================

DEFAULT_BACKUP_DIR: str = "backup"


def _resolve_export_path(vault_path: Path) -> Path:
    """Place bare filenames inside ``DEFAULT_BACKUP_DIR``.

    If the user types ``wifi.passport`` (no directory part), the vault lands
    in ``backup/wifi.passport``. If they type any explicit path - relative
    with a directory (``out/wifi.passport``), absolute (``D:\\elsewhere``),
    or a custom subfolder - we respect it verbatim.
    """
    if vault_path.parent == Path("."):
        return Path(DEFAULT_BACKUP_DIR) / vault_path
    return vault_path


def _resolve_input_path(vault_path: Path) -> Path:
    """Find an existing vault file: cwd first, then ``DEFAULT_BACKUP_DIR``.

    Symmetric with :func:`_resolve_export_path`. If the user types a bare
    ``wifi.passport`` and no such file exists in the current directory but
    ``backup/wifi.passport`` does, that's the one they almost certainly
    mean. Explicit paths are honored exactly as typed.
    """
    if vault_path.is_file():
        return vault_path
    if vault_path.parent == Path("."):
        fallback = Path(DEFAULT_BACKUP_DIR) / vault_path
        if fallback.is_file():
            return fallback
    return vault_path


def cmd_export(vault_path: Path, *, force: bool = False) -> int:
    """Implementation of ``wifi-passport export``."""
    require_windows()

    vault_path = _resolve_export_path(vault_path)

    if vault_path.exists() and not force:
        if input(f"'{vault_path}' exists. Overwrite? [y/N]: ").strip().lower() != "y":
            info("Aborted.")
            return 1

    info("Discovering WiFi profiles via WLAN API...")
    profiles = list_profile_xmls()
    if not profiles:
        fail("No WiFi profiles found on this machine.")
        return 1
    info(f"Found {len(profiles)} profile(s):")
    for ssid, _ in profiles:
        info(f"  - {ssid}")

    info("")
    warn("The passphrase protects ALL your WiFi credentials.")
    warn("Use a long passphrase you can recover (password manager recommended).")
    info("")
    passphrase = prompt_passphrase(confirm=True)

    info("\nValidating payload...")
    payload = build_payload(xml for _, xml in profiles)
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    info(f"  -> payload: {len(plaintext):,} bytes plaintext.")

    params = KdfParams()
    info(f"Deriving key with {params.describe()}...")
    t0 = perf_counter()
    blob = encrypt_blob(plaintext, passphrase, params)
    info(f"  -> KDF + encryption: {perf_counter() - t0:.2f}s")

    atomic_write(vault_path, blob)
    success(f"Vault written: {vault_path}  ({len(blob):,} bytes)")
    info(f"  Verify with:  python {Path(sys.argv[0]).name} verify {vault_path}")
    return 0


def _load_and_decrypt(vault_path: Path) -> dict[str, Any]:
    """Read a vault file, prompt for the passphrase, decrypt and validate."""
    vault_path = _resolve_input_path(vault_path)
    if not vault_path.is_file():
        raise SystemExit(f"ERROR: file not found: {vault_path}")
    size = vault_path.stat().st_size
    if size > MAX_VAULT_BYTES:
        raise SystemExit(f"ERROR: file too large ({size} bytes).")

    blob = vault_path.read_bytes()
    # Show the KDF parameters before asking for the passphrase - gives the
    # user a chance to abort if the file looks unexpected.
    try:
        params, _, _ = _unpack_header(blob[:HEADER_SIZE])
        info(f"Vault KDF: {params.describe()}")
    except VaultFormatError as e:
        raise SystemExit(f"ERROR: {e}")

    passphrase = getpass.getpass("Passphrase: ")

    info("Decrypting & authenticating...")
    t0 = perf_counter()
    try:
        plaintext = decrypt_blob(blob, passphrase)
    except (VaultFormatError, AuthenticationError) as e:
        raise SystemExit(f"ERROR: {e}")
    info(f"  -> done in {perf_counter() - t0:.2f}s")

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise SystemExit(f"ERROR: decrypted data is not valid JSON: {e}")

    info("Validating payload schema...")
    try:
        validate_payload(payload)
    except PayloadError as e:
        raise SystemExit(f"ERROR: invalid payload: {e}")

    return payload


def cmd_inspect(vault_path: Path) -> int:
    """Implementation of ``wifi-passport inspect``."""
    payload = _load_and_decrypt(vault_path)
    info("")
    info(f"Vault host:    {payload['host']}")
    info(f"Profile count: {payload['count']}")
    info("-" * 64)
    info(f"{'SSID':<34} {'Auth':<18} {'Key':<5}")
    info("-" * 64)
    for prof in payload["profiles"]:
        key_flag = "yes" if prof["has_key"] else "-"
        info(f"{prof['ssid'][:33]:<34} {prof['auth'][:17]:<18} {key_flag:<5}")
    return 0


def cmd_verify(vault_path: Path) -> int:
    """Implementation of ``wifi-passport verify``.

    Decrypts, validates schema, and re-parses each XML - but never touches
    the live WiFi configuration. Use this to confirm a backup is healthy
    before formatting your machine.
    """
    payload = _load_and_decrypt(vault_path)
    issues = 0
    for index, prof in enumerate(payload["profiles"]):
        try:
            validate_profile_xml(prof["xml"])
        except PayloadError as e:
            fail(f"  profile[{index}] ({prof['ssid']}): {e}")
            issues += 1
    if issues:
        fail(f"Verification FAILED - {issues} profile(s) malformed.")
        return 1
    success(
        f"All checks passed. Vault holds {payload['count']} valid profile(s)."
    )
    return 0


def cmd_import(vault_path: Path, *, force: bool = False) -> int:
    """Implementation of ``wifi-passport import``."""
    require_windows()
    if not is_admin():
        warn("Not running as Administrator - `netsh wlan add profile` may fail.")
        if not force and input("Continue anyway? [y/N]: ").strip().lower() != "y":
            info("Aborted. Re-launch from an elevated PowerShell.")
            return 1

    payload = _load_and_decrypt(vault_path)
    info("")
    info(f"About to import {payload['count']} profile(s) from vault "
         f"created on '{payload['host']}':")
    for prof in payload["profiles"]:
        info(f"  - {prof['ssid']}  ({prof['auth']})")

    if not force and input("\nProceed? [y/N]: ").strip().lower() != "y":
        info("Aborted.")
        return 1

    imported = 0
    failures: list[tuple[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="wifipass_import_") as tmp:
        tmpdir = Path(tmp)
        for index, prof in enumerate(payload["profiles"]):
            xml_path = tmpdir / safe_xml_filename(index, prof["ssid"])
            xml_path.write_text(prof["xml"], encoding="utf-8")
            try:
                import_profile_xml(xml_path)
                success(f"  {prof['ssid']}")
                imported += 1
            except NetshError as e:
                fail(f"  {prof['ssid']}: {str(e).splitlines()[0]}")
                failures.append((prof["ssid"], str(e)))

    info("")
    info(f"Imported {imported}/{payload['count']}.")
    if failures:
        fail(f"Failures: {len(failures)}")
        return 1
    return 0


def cmd_benchmark() -> int:
    """Implementation of ``wifi-passport benchmark``."""
    info("Argon2id benchmark on this machine")
    info("-" * 64)
    info(f"{'time':>5}  {'mem MiB':>9}  {'p':>3}  {'duration':>10}")
    info("-" * 64)

    salt = secrets.token_bytes(SALT_BYTES)
    test_passphrase = "benchmark-passphrase-not-secret-x"

    configurations = [
        (2,  64 * 1024, 1),
        (3, 128 * 1024, 2),
        (4, 256 * 1024, 2),   # current default
        (6, 512 * 1024, 4),
    ]
    for t, m_kib, p in configurations:
        params = KdfParams(time_cost=t, memory_kib=m_kib, parallelism=p)
        t0 = perf_counter()
        derive_key(test_passphrase, salt, params)
        elapsed = perf_counter() - t0
        mark = "  <- default" if (t, m_kib, p) == (
            DEFAULT_ARGON2_TIME,
            DEFAULT_ARGON2_MEMORY_KIB,
            DEFAULT_ARGON2_PARALLELISM,
        ) else ""
        info(f"{t:>5}  {m_kib // 1024:>9}  {p:>3}  {elapsed:>9.2f}s{mark}")
    info("-" * 64)
    info("Pick a config that takes ~0.5-2.0s on your machine.")
    return 0


# ===========================================================================
# CLI entry point
# ===========================================================================

def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level ``argparse`` parser."""
    parser = argparse.ArgumentParser(
        prog="wifi-passport",
        description=(
            "Wifi-Passport - encrypted vault for Windows WiFi credentials. "
            "AES-256-GCM with Argon2id key derivation."
        ),
        epilog=(
            "Examples:\n"
            "  wifi-passport export wifi.passport     # back up all profiles\n"
            "  wifi-passport verify wifi.passport     # check backup is healthy\n"
            "  wifi-passport inspect wifi.passport    # list without importing\n"
            "  wifi-passport import wifi.passport     # restore (run as Admin)\n"
            "  wifi-passport benchmark                # tune Argon2 params\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"wifi-passport {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_export = sub.add_parser("export", help="Export all profiles to a vault.")
    p_export.add_argument("vault", type=Path, help="Output vault file")
    p_export.add_argument("--force", action="store_true",
                          help="Overwrite an existing vault without prompting")

    p_import = sub.add_parser("import", help="Restore profiles from a vault.")
    p_import.add_argument("vault", type=Path, help="Input vault file")
    p_import.add_argument("--force", action="store_true",
                          help="Skip confirmation prompts")

    p_inspect = sub.add_parser(
        "inspect", help="Decrypt and list vault contents without importing."
    )
    p_inspect.add_argument("vault", type=Path, help="Input vault file")

    p_verify = sub.add_parser(
        "verify", help="Confirm a vault decrypts cleanly and is well-formed."
    )
    p_verify.add_argument("vault", type=Path, help="Input vault file")

    sub.add_parser(
        "benchmark", help="Time Argon2id parameter sets on this machine."
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a Unix-style exit code."""
    args = build_parser().parse_args(argv)
    try:
        if args.command == "export":
            return cmd_export(args.vault, force=args.force)
        if args.command == "import":
            return cmd_import(args.vault, force=args.force)
        if args.command == "inspect":
            return cmd_inspect(args.vault)
        if args.command == "verify":
            return cmd_verify(args.vault)
        if args.command == "benchmark":
            return cmd_benchmark()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except VaultError as e:
        fail(str(e))
        return 1
    return 0


if __name__ == "__main__":   # pragma: no cover
    sys.exit(main())
