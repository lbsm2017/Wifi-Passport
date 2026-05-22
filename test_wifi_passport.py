#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test suite for ``wifi_passport``.

Runs in two modes:

* ``pytest test_wifi_passport.py``    — full pytest reporting
* ``python test_wifi_passport.py``    — minimal stdlib runner (no pytest dep)

All tests run on any OS; the few Windows-only paths (netsh, is_admin) are
exercised through pure functions and skipped where they touch ``subprocess``.
"""

from __future__ import annotations

import json
import struct
import sys
import tempfile
from pathlib import Path

# Ensure wifi_passport.py is importable when the test file is run directly.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wifi_passport as t  # noqa: E402


# ===========================================================================
# Fixtures and helpers
# ===========================================================================

VALID_XML = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>HomeWifi</name>
  <SSIDConfig>
    <SSID>
      <name>HomeWifi</name>
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>my-actual-password</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>"""

VALID_XML_ALT = VALID_XML.replace("HomeWifi", "OfficeWifi")

# Use very cheap Argon2 params in tests so the suite stays fast.
FAST_PARAMS = t.KdfParams(time_cost=1, memory_kib=8 * 1024, parallelism=1)

GOOD_PASSPHRASE = "Tr0ub4dor&3lephant!"     # passes all validators


def make_payload(profiles: int = 2) -> dict:
    """Build a valid payload of N synthetic profiles."""
    items = []
    for i in range(profiles):
        ssid = f"Network{i}"
        xml = VALID_XML.replace("HomeWifi", ssid)
        items.append({"ssid": ssid, "auth": "WPA2PSK", "has_key": True, "xml": xml})
    return {"version": 1, "host": "test-host", "count": len(items), "profiles": items}


# ===========================================================================
# Passphrase validation
# ===========================================================================

class TestPassphrase:
    """Behavior of :func:`wifi_passport.validate_passphrase`."""

    def test_strong_passphrase_accepted(self) -> None:
        audit = t.validate_passphrase("Tr0ub4dor&3lephant!Fortress")
        assert audit.acceptable, (audit.score, audit.issues)
        assert audit.score >= 70
        assert audit.label in {"strong", "excellent"}

    def test_long_diceware_style_accepted(self) -> None:
        audit = t.validate_passphrase("correct horse battery staple 42!")
        assert audit.acceptable
        assert audit.entropy_bits > 60

    def test_too_short_rejected(self) -> None:
        audit = t.validate_passphrase("Short1!")
        assert not audit.acceptable
        assert any("Too short" in i for i in audit.issues)

    def test_single_class_rejected(self) -> None:
        audit = t.validate_passphrase("alllowercaseletters")
        assert not audit.acceptable
        assert any("character classes" in i for i in audit.issues)

    def test_common_token_rejected(self) -> None:
        audit = t.validate_passphrase("Password12345678!")
        assert not audit.acceptable
        assert any("weak token" in i for i in audit.issues)

    def test_keyboard_pattern_rejected(self) -> None:
        audit = t.validate_passphrase("Hello.qwertyuiop12")
        assert not audit.acceptable
        assert any("keyboard pattern" in i for i in audit.issues)

    def test_repetition_warning(self) -> None:
        audit = t.validate_passphrase("Aaaaa9999!XyZqWvB")
        assert any("sequential or repeated" in w for w in audit.warnings)

    def test_whitespace_edges_rejected(self) -> None:
        audit = t.validate_passphrase(" Tr0ub4dor&3lephant! ")
        assert not audit.acceptable
        assert any("whitespace" in i for i in audit.issues)

    def test_score_bounds(self) -> None:
        for pw in ["", "a", "x" * 100, GOOD_PASSPHRASE, "Aa1!" * 8]:
            audit = t.validate_passphrase(pw)
            assert 0 <= audit.score <= 100

    def test_entropy_estimate_is_low_for_repeats(self) -> None:
        repetitive = t.validate_passphrase("Aa1!" * 6)
        diverse = t.validate_passphrase("J7#mVq.pL2dKxR$wEz")
        assert diverse.entropy_bits > repetitive.entropy_bits


# ===========================================================================
# KdfParams
# ===========================================================================

class TestKdfParams:
    """Range checks for KDF parameter validation."""

    def test_defaults_pass(self) -> None:
        t.KdfParams().validate()

    def test_time_cost_out_of_range(self) -> None:
        try:
            t.KdfParams(time_cost=0).validate()
        except t.VaultFormatError:
            return
        raise AssertionError("expected VaultFormatError")

    def test_memory_too_low(self) -> None:
        try:
            t.KdfParams(memory_kib=1024).validate()
        except t.VaultFormatError:
            return
        raise AssertionError("expected VaultFormatError")

    def test_memory_too_high(self) -> None:
        try:
            t.KdfParams(memory_kib=8 * 1024 * 1024).validate()
        except t.VaultFormatError:
            return
        raise AssertionError("expected VaultFormatError")

    def test_describe(self) -> None:
        s = t.KdfParams().describe()
        assert "Argon2id" in s and "MiB" in s


# ===========================================================================
# Crypto round-trip
# ===========================================================================

class TestCrypto:
    """End-to-end encryption/decryption behavior."""

    def test_roundtrip(self) -> None:
        plaintext = b"the rain in spain stays mainly in the plain" * 50
        blob = t.encrypt_blob(plaintext, GOOD_PASSPHRASE, FAST_PARAMS)
        assert blob[:8] == t.MAGIC
        assert len(blob) == t.HEADER_SIZE + len(plaintext) + t.GCM_TAG_BYTES
        recovered = t.decrypt_blob(blob, GOOD_PASSPHRASE)
        assert recovered == plaintext

    def test_empty_plaintext_roundtrip(self) -> None:
        blob = t.encrypt_blob(b"", GOOD_PASSPHRASE, FAST_PARAMS)
        assert t.decrypt_blob(blob, GOOD_PASSPHRASE) == b""

    def test_wrong_passphrase_rejected(self) -> None:
        blob = t.encrypt_blob(b"secret-payload", GOOD_PASSPHRASE, FAST_PARAMS)
        try:
            t.decrypt_blob(blob, "completely-different-passphrase-X1!")
        except t.AuthenticationError:
            return
        raise AssertionError("wrong passphrase was NOT rejected")

    def test_ciphertext_tampering_detected(self) -> None:
        blob = bytearray(t.encrypt_blob(b"x" * 256, GOOD_PASSPHRASE, FAST_PARAMS))
        blob[t.HEADER_SIZE + 10] ^= 0xFF
        try:
            t.decrypt_blob(bytes(blob), GOOD_PASSPHRASE)
        except t.AuthenticationError:
            return
        raise AssertionError("ciphertext tampering NOT detected")

    def test_tag_tampering_detected(self) -> None:
        blob = bytearray(t.encrypt_blob(b"x" * 256, GOOD_PASSPHRASE, FAST_PARAMS))
        blob[-1] ^= 0x01
        try:
            t.decrypt_blob(bytes(blob), GOOD_PASSPHRASE)
        except t.AuthenticationError:
            return
        raise AssertionError("tag tampering NOT detected")

    def test_header_tampering_detected(self) -> None:
        """
        Modifying the KDF iterations in the header changes both the derived
        key AND the GCM associated data, so decryption must fail.
        """
        blob = bytearray(t.encrypt_blob(b"x" * 256, GOOD_PASSPHRASE, FAST_PARAMS))
        # Bump the time_cost byte (offset 11 per HEADER_STRUCT)
        blob[11] = (blob[11] + 1) % 32
        try:
            t.decrypt_blob(bytes(blob), GOOD_PASSPHRASE)
        except (t.AuthenticationError, t.VaultFormatError):
            return
        raise AssertionError("header tampering NOT detected")

    def test_bad_magic_rejected(self) -> None:
        blob = bytearray(t.encrypt_blob(b"x", GOOD_PASSPHRASE, FAST_PARAMS))
        blob[:8] = b"NOPE\x00\x00\x00\x00"
        try:
            t.decrypt_blob(bytes(blob), GOOD_PASSPHRASE)
        except t.VaultFormatError as e:
            assert "magic" in str(e).lower()
            return
        raise AssertionError("bad magic NOT rejected")

    def test_truncated_file_rejected(self) -> None:
        blob = t.encrypt_blob(b"x" * 100, GOOD_PASSPHRASE, FAST_PARAMS)
        for cutoff in [0, 10, t.HEADER_SIZE, t.HEADER_SIZE + 1]:
            try:
                t.decrypt_blob(blob[:cutoff], GOOD_PASSPHRASE)
            except (t.VaultFormatError, t.AuthenticationError):
                continue
            raise AssertionError(f"truncated file at {cutoff} NOT rejected")

    def test_oversized_blob_rejected(self) -> None:
        oversized = b"\x00" * (t.MAX_VAULT_BYTES + 1)
        try:
            t.decrypt_blob(oversized, GOOD_PASSPHRASE)
        except t.VaultFormatError:
            return
        raise AssertionError("oversized blob NOT rejected")

    def test_unique_salt_and_nonce_per_encryption(self) -> None:
        """Two encryptions of identical plaintext must produce different blobs."""
        a = t.encrypt_blob(b"same", GOOD_PASSPHRASE, FAST_PARAMS)
        b = t.encrypt_blob(b"same", GOOD_PASSPHRASE, FAST_PARAMS)
        assert a != b
        # Headers also differ: salt at offset 17, nonce at offset 33
        assert a[17:33] != b[17:33], "salt must differ"
        assert a[33:45] != b[33:45], "nonce must differ"

    def test_non_default_kdf_params_roundtrip(self) -> None:
        params = t.KdfParams(time_cost=2, memory_kib=16 * 1024, parallelism=2)
        blob = t.encrypt_blob(b"payload", GOOD_PASSPHRASE, params)
        parsed, _, _ = t._unpack_header(blob[: t.HEADER_SIZE])
        assert parsed == params
        assert t.decrypt_blob(blob, GOOD_PASSPHRASE) == b"payload"


# ===========================================================================
# Header parsing
# ===========================================================================

class TestHeader:
    """Direct unit tests on the header encoder/decoder."""

    def _good_header(self) -> bytes:
        return t._pack_header(FAST_PARAMS, b"\x01" * 16, b"\x02" * 12)

    def test_pack_unpack_roundtrip(self) -> None:
        h = self._good_header()
        params, salt, nonce = t._unpack_header(h)
        assert params == FAST_PARAMS
        assert salt == b"\x01" * 16
        assert nonce == b"\x02" * 12

    def test_unsupported_version(self) -> None:
        h = bytearray(self._good_header())
        h[8:10] = struct.pack(">H", 999)
        try:
            t._unpack_header(bytes(h))
        except t.VaultFormatError as e:
            assert "version" in str(e)
            return
        raise AssertionError

    def test_unsupported_kdf(self) -> None:
        h = bytearray(self._good_header())
        h[10] = 99
        try:
            t._unpack_header(bytes(h))
        except t.VaultFormatError as e:
            assert "KDF" in str(e)
            return
        raise AssertionError


# ===========================================================================
# Profile XML & payload schema
# ===========================================================================

class TestProfileXml:
    """Validation of individual ``WLANProfile`` XMLs."""

    def test_valid_profile_parses(self) -> None:
        ssid, auth, has_key = t.validate_profile_xml(VALID_XML)
        assert ssid == "HomeWifi"
        assert auth == "WPA2PSK"
        assert has_key is True

    def test_open_network_has_no_key(self) -> None:
        # Strip the sharedKey block to simulate an open network.
        open_xml = VALID_XML.replace(
            "<sharedKey>", "<!--"
        ).replace("</sharedKey>", "-->")
        ssid, auth, has_key = t.validate_profile_xml(open_xml)
        assert ssid == "HomeWifi" and has_key is False

    def test_malformed_xml(self) -> None:
        try:
            t.validate_profile_xml("<not><well-formed>")
        except t.PayloadError:
            return
        raise AssertionError

    def test_wrong_root(self) -> None:
        try:
            t.validate_profile_xml("<Foo><name>x</name></Foo>")
        except t.PayloadError:
            return
        raise AssertionError

    def test_missing_name(self) -> None:
        no_name = VALID_XML.replace("<name>HomeWifi</name>", "", 1)
        no_name = no_name.replace("<name>HomeWifi</name>", "")
        try:
            t.validate_profile_xml(no_name)
        except t.PayloadError:
            return
        raise AssertionError

    def test_billion_laughs_rejected(self) -> None:
        """Recursive entity expansion (Billion Laughs / XML bomb) must NOT
        be expanded by the parser. defusedxml refuses the document outright."""
        bomb = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<WLANProfile><name>&lol3;</name></WLANProfile>"""
        try:
            t.validate_profile_xml(bomb)
        except t.PayloadError:
            return
        raise AssertionError("Billion Laughs payload was NOT rejected")

    def test_external_entity_rejected(self) -> None:
        """XML External Entity (XXE) - parser must refuse to fetch the URL
        and must not silently substitute the entity."""
        xxe = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<WLANProfile><name>&xxe;</name></WLANProfile>"""
        try:
            t.validate_profile_xml(xxe)
        except t.PayloadError:
            return
        raise AssertionError("XXE payload was NOT rejected")


class TestPayloadSchema:
    """Validation of the top-level JSON payload."""

    def test_minimal_valid_payload(self) -> None:
        t.validate_payload(make_payload(1))

    def test_multi_profile_payload(self) -> None:
        t.validate_payload(make_payload(5))

    def test_root_must_be_object(self) -> None:
        try:
            t.validate_payload([1, 2, 3])
        except t.PayloadError:
            return
        raise AssertionError

    def test_missing_field(self) -> None:
        bad = make_payload(1)
        del bad["host"]
        try:
            t.validate_payload(bad)
        except t.PayloadError as e:
            assert "host" in str(e)
            return
        raise AssertionError

    def test_count_mismatch(self) -> None:
        bad = make_payload(2)
        bad["count"] = 99
        try:
            t.validate_payload(bad)
        except t.PayloadError as e:
            assert "count" in str(e)
            return
        raise AssertionError

    def test_version_mismatch(self) -> None:
        bad = make_payload(1)
        bad["version"] = 99
        try:
            t.validate_payload(bad)
        except t.PayloadError:
            return
        raise AssertionError

    def test_duplicate_ssid_detected(self) -> None:
        bad = make_payload(2)
        bad["profiles"][1]["ssid"] = bad["profiles"][0]["ssid"]
        # Make the XML match to isolate the dup check
        bad["profiles"][1]["xml"] = bad["profiles"][0]["xml"]
        try:
            t.validate_payload(bad)
        except t.PayloadError as e:
            assert "duplicate" in str(e).lower()
            return
        raise AssertionError

    def test_ssid_mismatch_with_xml(self) -> None:
        bad = make_payload(1)
        bad["profiles"][0]["ssid"] = "LiarLiar"  # wrapper says one thing, XML another
        try:
            t.validate_payload(bad)
        except t.PayloadError as e:
            assert "SSID mismatch" in str(e)
            return
        raise AssertionError


# ===========================================================================
# Build payload from XML strings
# ===========================================================================

class TestBuildPayload:
    """Bundle XML strings into a vault payload and validate."""

    def test_build_from_xml_strings(self) -> None:
        payload = t.build_payload([VALID_XML, VALID_XML_ALT])
        assert payload["count"] == 2
        ssids = {p["ssid"] for p in payload["profiles"]}
        assert ssids == {"HomeWifi", "OfficeWifi"}

    def test_full_pipeline_encrypt_decrypt(self) -> None:
        payload = t.build_payload([VALID_XML])
        plaintext = json.dumps(payload).encode("utf-8")
        blob = t.encrypt_blob(plaintext, GOOD_PASSPHRASE, FAST_PARAMS)
        recovered = json.loads(t.decrypt_blob(blob, GOOD_PASSPHRASE))
        t.validate_payload(recovered)
        assert recovered["profiles"][0]["ssid"] == "HomeWifi"

    def test_ssid_with_illegal_filename_chars_roundtrips(self) -> None:
        """The whole point of the WLAN-API refactor: SSIDs containing
        ``:`` (or any other char Windows forbids in filenames) must not be
        dropped by build_payload. The XML carries the SSID inside two
        <name> elements; both must say the literal SSID."""
        gnarly_ssid = "b2:4a:39:80:9c:23"
        xml = VALID_XML.replace("HomeWifi", gnarly_ssid)
        payload = t.build_payload([xml])
        assert payload["count"] == 1
        assert payload["profiles"][0]["ssid"] == gnarly_ssid

        # Round-trip end to end so we also prove the SSID survives JSON +
        # AES-GCM + schema-revalidation.
        blob = t.encrypt_blob(
            json.dumps(payload).encode("utf-8"),
            GOOD_PASSPHRASE,
            FAST_PARAMS,
        )
        recovered = json.loads(t.decrypt_blob(blob, GOOD_PASSPHRASE))
        t.validate_payload(recovered)
        assert recovered["profiles"][0]["ssid"] == gnarly_ssid


# ===========================================================================
# Atomic file I/O
# ===========================================================================

class TestAtomicWrite:
    """Atomicity contract of :func:`wifi_passport.atomic_write`."""

    def test_creates_file_with_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.bin"
            t.atomic_write(path, b"hello world")
            assert path.read_bytes() == b"hello world"

    def test_overwrites_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.bin"
            t.atomic_write(path, b"old")
            t.atomic_write(path, b"new")
            assert path.read_bytes() == b"new"

    def test_no_tmp_file_left_behind_on_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.bin"
            t.atomic_write(path, b"x")
            leftovers = list(Path(tmp).glob("*.tmp"))
            assert leftovers == [], f"stray tmp files: {leftovers}"


# ===========================================================================
# safe_xml_filename — collision-free import filenames
# ===========================================================================

class TestSafeXmlFilename:
    """Behavior of :func:`wifi_passport.safe_xml_filename`."""

    def test_basic_sanitization(self) -> None:
        assert t.safe_xml_filename(0, "HomeWifi") == "000_HomeWifi.xml"

    def test_spaces_become_underscores(self) -> None:
        assert t.safe_xml_filename(1, "Wifi A") == "001_Wifi_A.xml"

    def test_empty_ssid_falls_back(self) -> None:
        assert t.safe_xml_filename(0, "") == "000_profile.xml"

    def test_all_symbols_ssid_becomes_underscores(self) -> None:
        # Every forbidden char becomes "_", so the sanitized core is a string
        # of underscores. The "profile" fallback only fires for an empty SSID.
        assert t.safe_xml_filename(2, "!@#$%^&*()") == "002___________.xml"

    def test_collision_resolved_by_index(self) -> None:
        """Two SSIDs sanitizing to the same body get distinct filenames."""
        a = t.safe_xml_filename(0, "Wifi A")
        b = t.safe_xml_filename(1, "Wifi_A")
        assert a != b
        assert a.endswith("_Wifi_A.xml") and b.endswith("_Wifi_A.xml")

    def test_index_zero_padded_for_sort_order(self) -> None:
        assert t.safe_xml_filename(7, "x").startswith("007_")
        assert t.safe_xml_filename(123, "x").startswith("123_")


# ===========================================================================
# Export-path resolution (default backup/ folder)
# ===========================================================================

class TestResolveExportPath:
    """Behavior of :func:`wifi_passport._resolve_export_path`."""

    def test_bare_filename_goes_into_backup(self) -> None:
        assert t._resolve_export_path(Path("wifi.passport")) == \
            Path(t.DEFAULT_BACKUP_DIR) / "wifi.passport"

    def test_relative_with_directory_is_preserved(self) -> None:
        explicit = Path("out") / "wifi.passport"
        assert t._resolve_export_path(explicit) == explicit

    def test_explicit_backup_subpath_is_preserved(self) -> None:
        # User typed `backup/wifi.passport` themselves - don't double it.
        explicit = Path(t.DEFAULT_BACKUP_DIR) / "wifi.passport"
        assert t._resolve_export_path(explicit) == explicit

    def test_absolute_path_is_preserved(self) -> None:
        # Use a platform-appropriate absolute path.
        abs_path = (Path("/tmp") if sys.platform != "win32"
                    else Path("C:/tmp")) / "wifi.passport"
        assert t._resolve_export_path(abs_path) == abs_path


# ===========================================================================
# Input-path resolution (read commands look in backup/ as a fallback)
# ===========================================================================

import os as _os


class TestResolveInputPath:
    """Behavior of :func:`wifi_passport._resolve_input_path`."""

    def test_returns_existing_file_in_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = _os.getcwd()
            _os.chdir(tmp)
            try:
                Path("wifi.passport").write_bytes(b"x")
                assert t._resolve_input_path(Path("wifi.passport")) == \
                    Path("wifi.passport")
            finally:
                _os.chdir(old_cwd)

    def test_falls_back_to_backup_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = _os.getcwd()
            _os.chdir(tmp)
            try:
                backup = Path(t.DEFAULT_BACKUP_DIR)
                backup.mkdir()
                (backup / "wifi.passport").write_bytes(b"x")
                assert t._resolve_input_path(Path("wifi.passport")) == \
                    backup / "wifi.passport"
            finally:
                _os.chdir(old_cwd)

    def test_missing_file_returns_input_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = _os.getcwd()
            _os.chdir(tmp)
            try:
                # Nothing exists anywhere - caller will surface "file not found".
                assert t._resolve_input_path(Path("nope.passport")) == \
                    Path("nope.passport")
            finally:
                _os.chdir(old_cwd)

    def test_explicit_path_does_not_get_backup_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = _os.getcwd()
            _os.chdir(tmp)
            try:
                # Even if backup/x.passport existed, an explicit out/x.passport
                # request must NOT silently redirect.
                backup = Path(t.DEFAULT_BACKUP_DIR)
                backup.mkdir()
                (backup / "x.passport").write_bytes(b"x")
                explicit = Path("out") / "x.passport"
                assert t._resolve_input_path(explicit) == explicit
            finally:
                _os.chdir(old_cwd)


# ===========================================================================
# CLI parser
# ===========================================================================

class TestCli:
    """Surface-level CLI parser checks (no commands actually executed)."""

    def test_parser_builds(self) -> None:
        parser = t.build_parser()
        args = parser.parse_args(["export", "x.passport"])
        assert args.command == "export"
        assert args.vault == Path("x.passport")
        assert args.force is False

    def test_force_flag(self) -> None:
        args = t.build_parser().parse_args(["import", "x.passport", "--force"])
        assert args.force is True

    def test_subcommand_required(self) -> None:
        parser = t.build_parser()
        try:
            parser.parse_args([])
        except SystemExit:
            return
        raise AssertionError


# ===========================================================================
# Standalone test runner (when invoked directly, no pytest)
# ===========================================================================

def _run_standalone() -> int:
    """Tiny test runner so the file works without pytest installed."""
    import inspect, traceback

    classes = [
        v for k, v in globals().items()
        if k.startswith("Test") and inspect.isclass(v)
    ]
    passed = failed = 0
    failures: list[tuple[str, str]] = []

    for cls in classes:
        instance = cls()
        for name in sorted(dir(instance)):
            if not name.startswith("test_"):
                continue
            method = getattr(instance, name)
            label = f"{cls.__name__}.{name}"
            try:
                method()
                passed += 1
                print(f"  \033[32m[ok]\033[0m  {label}")
            except Exception:
                failed += 1
                failures.append((label, traceback.format_exc()))
                print(f"  \033[31m[xx]\033[0m  {label}")

    print()
    print(f"Passed: {passed}    Failed: {failed}")
    for label, tb in failures:
        print(f"\n-- {label} " + "-" * (60 - len(label)))
        print(tb)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(_run_standalone())
