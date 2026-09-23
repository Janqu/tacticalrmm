"""Generate deterministic Django/PyOTP fixtures (no database or app settings).

uv run --with django==4.2.30 --with argon2-cffi --with bcrypt --with pyotp==2.9.0 tools/auth_vectors.py
"""

import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings
from django.contrib.auth.hashers import (
    Argon2PasswordHasher,
    BCryptSHA256PasswordHasher,
    PBKDF2PasswordHasher,
    PBKDF2SHA1PasswordHasher,
    ScryptPasswordHasher,
    check_password,
)
import pyotp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    settings.configure()
    password = " pässword🔑 " + "long" * 24
    salt = "abcdefghijklmnopqrstuv"
    hashes = [
        PBKDF2PasswordHasher().encode(password, salt),
        PBKDF2PasswordHasher().encode(password, "short", iterations=12000),
        PBKDF2PasswordHasher().encode(password, salt, iterations=720000),
        PBKDF2SHA1PasswordHasher().encode(password, salt),
        Argon2PasswordHasher().encode(password, salt),
        BCryptSHA256PasswordHasher().encode(password, b"$2b$12$abcdefghijklmnopqrstuu"),
        ScryptPasswordHasher().encode(password, salt),
    ]
    passwords = []
    for encoded in hashes:
        for candidate in (password, password.strip(), "wrong", ""):
            upgrades = []
            valid = check_password(candidate, encoded, setter=upgrades.append)
            passwords.append(dict(password=candidate, encoded=encoded, valid=valid, upgrade=bool(upgrades)))
    for encoded in ("", "!unusable", "md5$salt$invalid"):
        passwords.append(dict(password=password, encoded=encoded, valid=check_password(password, encoded), upgrade=False))

    at = 1700000010
    secret = "JBSWY3DPEHPK3PXP"
    otp = pyotp.TOTP(secret)
    tokens = [otp.at(at + step * 30) for step in (-11, -10, -1, 0, 1, 10, 11)]
    tokens += ["".join(chr(ord(c) + 0xFEE0) for c in otp.at(at)), " " + otp.at(at), "000000", "", "1234567"]
    totp = [dict(secret=secret, token=token, at=at, valid=otp.verify(token, datetime.fromtimestamp(at, timezone.utc), valid_window=10)) for token in tokens]
    for key in (secret.lower(), "MZXW6===", "mzxw6"):
        otp = pyotp.TOTP(key)
        totp.append(dict(secret=key, token=otp.at(at), at=at, valid=True))
    target = Path(__file__).resolve().parents[1] / "internal/accounts/testdata/auth_vectors.json"
    content = json.dumps(dict(passwords=passwords, totp=totp), ensure_ascii=False, indent=2) + "\n"
    if args.check:
        if target.read_text() != content:
            raise SystemExit("Authentication reference vectors differ; review before regenerating")
    else:
        target.parent.mkdir(exist_ok=True)
        target.write_text(content)
    print(f"Verified {len(passwords)} password and {len(totp)} TOTP reference cases")


if __name__ == "__main__":
    main()
