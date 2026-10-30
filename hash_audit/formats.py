"""Conservative syntax recognition and backend-specific hash serialization.

Recognition is only a list of supported possibilities, never proof of the
algorithm. In particular, digest length cannot identify an unsalted algorithm.
Registry mappings follow Hashcat's example-hashes reference and John Jumbo's
format sources; installed backend versions may support a smaller selection.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class HashFormat:
    key: str
    label: str
    hashcat_mode: int
    john_format: str | None


_FORMATS = (
    HashFormat("md5", "MD5 (raw)", 0, "raw-md5"),
    HashFormat("sha1", "SHA-1 (raw)", 100, "raw-sha1"),
    HashFormat("sha256", "SHA-256 (raw)", 1400, "raw-sha256"),
    HashFormat("sha512", "SHA-512 (raw)", 1700, "raw-sha512"),
    HashFormat("ntlm", "NTLM / NT hash", 1000, "nt"),
    HashFormat("mysql323", "MySQL pre-4.1", 200, "mysql"),
    HashFormat("mysql41", "MySQL 4.1/5 PASSWORD()", 300, "mysql-sha1"),
    HashFormat("phpass", "WordPress/phpBB portable phpass", 400, "phpass"),
    HashFormat("bcrypt", "bcrypt", 3200, "bcrypt"),
    HashFormat("wordpress-bcrypt", "WordPress bcrypt + HMAC-SHA384", 35500, None),
    HashFormat("md5crypt", "Unix MD5 crypt ($1$)", 500, "md5crypt-long"),
    HashFormat("apr1", "Apache MD5 crypt ($apr1$)", 1600, "md5crypt-long"),
    HashFormat("sha256crypt", "Unix SHA-256 crypt ($5$)", 7400, "sha256crypt"),
    HashFormat("sha512crypt", "Unix SHA-512 crypt ($6$)", 1800, "sha512crypt"),
    HashFormat("django-pbkdf2-sha256", "Django PBKDF2-SHA256", 10000, "Django"),
    HashFormat("md5-pass-salt", "MD5(password + salt)", 10, None),
    HashFormat("md5-salt-pass", "MD5(salt + password)", 20, None),
    HashFormat("sha1-pass-salt", "SHA-1(password + salt)", 110, None),
    HashFormat("sha1-salt-pass", "SHA-1(salt + password)", 120, None),
    HashFormat("sha256-pass-salt", "SHA-256(password + salt)", 1410, None),
    HashFormat("sha256-salt-pass", "SHA-256(salt + password)", 1420, None),
    HashFormat("sha512-pass-salt", "SHA-512(password + salt)", 1710, None),
    HashFormat("sha512-salt-pass", "SHA-512(salt + password)", 1720, None),
)
FORMATS: dict[str, HashFormat] = {item.key: item for item in _FORMATS}

_HEX_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128,
                "ntlm": 32, "mysql323": 16}
_CRYPT_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_CRYPT_CHARS = r"[./0-9A-Za-z]"
_BCRYPT = re.compile(r"\$2[abxy]\$([0-9]{2})\$[./0-9A-Za-z]{53}")
_DJANGO = re.compile(
    r"pbkdf2_sha256\$([1-9][0-9]{0,9})\$([!-~]{1,31})\$([A-Za-z0-9+/]{43}=)"
)


def _hex(value: str, length: int) -> bool:
    return len(value) == length and re.fullmatch(r"[0-9a-fA-F]+", value) is not None


def _bcrypt(value: str) -> bool:
    match = _BCRYPT.fullmatch(value)
    return match is not None and 4 <= int(match[1]) <= 31


def _django(value: str) -> bool:
    match = _DJANGO.fullmatch(value)
    if match is None or int(match[1]) > 2_147_483_647:
        return False
    # These characters are delimiters in either native Django or John's adapter.
    if any(char in match[2] for char in "$*:"):
        return False
    try:
        digest = base64.b64decode(match[3], validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(digest) == 32 and base64.b64encode(digest).decode("ascii") == match[3]


def validate(value: str, fmt: HashFormat) -> bool:
    """Validate a single hash without trimming or evaluating any input.

    Salted raw digests use ``hex:salt`` with 1..256 printable ASCII salt
    characters, excluding colon. Django salts use a portable 1..31 character
    subset accepted by both backends. Backend parsers remain authoritative.
    """
    if not isinstance(value, str) or not value or len(value) > 4096:
        return False
    if any(ord(char) < 32 or ord(char) > 126 for char in value):
        return False
    key = fmt.key
    if key not in FORMATS or FORMATS[key] != fmt:
        return False
    if key in _HEX_LENGTHS:
        return _hex(value, _HEX_LENGTHS[key])
    if key == "mysql41":
        return _hex(value[1:] if value.startswith("*") else value, 40)
    if key == "bcrypt":
        return _bcrypt(value)
    if key == "wordpress-bcrypt":
        return value.startswith("$wp$") and _bcrypt("$" + value[4:])
    if key == "phpass":
        return (
            re.fullmatch(r"\$[PH]\$" + _CRYPT_CHARS + "{31}", value) is not None
            and 7 <= _CRYPT_ALPHABET.index(value[3]) <= 31
        )
    if key in {"md5crypt", "apr1"}:
        prefix = "1" if key == "md5crypt" else "apr1"
        return re.fullmatch(
            r"\$" + prefix + r"\$" + _CRYPT_CHARS + r"{0,8}\$" + _CRYPT_CHARS + "{22}",
            value,
        ) is not None
    if key in {"sha256crypt", "sha512crypt"}:
        marker, digest_length = ("5", 43) if key == "sha256crypt" else ("6", 86)
        match = re.fullmatch(
            r"\$" + marker + r"\$(?:rounds=([1-9][0-9]{0,8})\$)?"
            + _CRYPT_CHARS + r"{0,16}\$" + _CRYPT_CHARS + "{" + str(digest_length) + "}",
            value,
        )
        return match is not None and (match[1] is None or 1000 <= int(match[1]) <= 999_999_999)
    if key == "django-pbkdf2-sha256":
        return _django(value)
    if key.endswith(("-pass-salt", "-salt-pass")):
        digest, separator, salt = value.partition(":")
        return (
            bool(separator)
            and _hex(digest, _HEX_LENGTHS[key.split("-", 1)[0]])
            and 1 <= len(salt) <= 256
            and ":" not in salt
        )
    return False


def candidates(value: str) -> list[HashFormat]:
    """Return all syntactically compatible supported formats in registry order."""
    return [fmt for fmt in FORMATS.values() if validate(value, fmt)]


def normalize(value: str, fmt: HashFormat, backend: str) -> str:
    """Serialize a validated hash for a supported backend, preserving salts."""
    if backend not in {"hashcat", "john"}:
        raise ValueError("Backend must be hashcat or john.")
    if not validate(value, fmt):
        raise ValueError(f"Invalid {fmt.key} hash.")
    if backend == "john" and fmt.john_format is None:
        raise ValueError(f"{fmt.key} is supported through Hashcat only.")
    if fmt.key == "mysql41":
        digest = value.removeprefix("*")
        return "*" + digest.upper() if backend == "john" else digest.lower()
    if fmt.key == "django-pbkdf2-sha256":
        if backend == "john":
            return "$django$*1*" + value
        if int(value.split("$", 2)[1]) > 999_999:
            raise ValueError("Django counts above 999999 need John; Hashcat 7.x mode 10000 has a six-digit limit.")
    if fmt.key in _HEX_LENGTHS:
        return value.lower()
    if fmt.key.endswith(("-pass-salt", "-salt-pass")):
        digest, salt = value.split(":", 1)
        return digest.lower() + ":" + salt
    return value
