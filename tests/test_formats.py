import base64
import hashlib
import unittest

from hash_audit.formats import FORMATS, HashFormat, candidates, normalize, validate


class FormatTests(unittest.TestCase):
    def test_raw_ambiguity(self):
        self.assertEqual([item.key for item in candidates("a" * 32)], ["md5", "ntlm"])
        self.assertEqual([item.key for item in candidates("a" * 40)], ["sha1", "mysql41"])
        self.assertEqual([item.key for item in candidates("*" + "a" * 40)], ["mysql41"])

    def test_raw_formats(self):
        for key, length in (("md5", 32), ("sha1", 40), ("sha256", 64), ("sha512", 128),
                            ("ntlm", 32), ("mysql323", 16)):
            with self.subTest(key=key):
                self.assertTrue(validate("A" * length, FORMATS[key]))
                self.assertEqual(normalize("A" * length, FORMATS[key], "john"), "a" * length)
                self.assertFalse(validate("g" * length, FORMATS[key]))
                self.assertFalse(validate("a" * (length - 1), FORMATS[key]))

    def test_mysql_normalization(self):
        for value in ("a" * 40, "*" + "a" * 40):
            self.assertEqual(normalize(value, FORMATS["mysql41"], "hashcat"), "a" * 40)
            self.assertEqual(normalize(value, FORMATS["mysql41"], "john"), "*" + "A" * 40)

    def test_known_structured_examples(self):
        samples = {
            "phpass": "$P$9d2OMJEOHyPg11MeSv46hashcatG.F1",
            "bcrypt": "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
            "wordpress-bcrypt": "$wp$2y$10$lzlQrRRhLSjz486bA9CKHuZRPoKz4uviT251Sq/r5OzKUBbrXwnQW",
            "md5crypt": "$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1",
            "apr1": "$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.",
            "sha256crypt": "$5$rounds=5000$saltstring$" + "a" * 43,
            "sha512crypt": "$6$saltstring$" + "a" * 86,
        }
        for key, value in samples.items():
            with self.subTest(key=key):
                self.assertEqual([item.key for item in candidates(value)], [key])
                self.assertEqual(normalize(value, FORMATS[key], "hashcat"), value)
                self.assertFalse(validate(value + "x", FORMATS[key]))

    def test_phpass_count_and_prefix(self):
        template = "$P$9" + "a" * 30
        self.assertTrue(validate(template, FORMATS["phpass"]))
        self.assertTrue(validate("$H$T" + "a" * 30, FORMATS["phpass"]))
        for count in (".", "4", "U", "z"):
            self.assertFalse(validate("$P$" + count + "a" * 30, FORMATS["phpass"]))
        self.assertEqual(candidates("$X$9" + "a" * 30), [])

    def test_bcrypt_count_and_prefix(self):
        for marker in ("a", "b", "x", "y"):
            for count in ("04", "31"):
                self.assertTrue(validate(f"$2{marker}${count}$" + "a" * 53, FORMATS["bcrypt"]))
        for count in ("00", "03", "32", "99", "4", "AA"):
            self.assertFalse(validate(f"$2b${count}$" + "a" * 53, FORMATS["bcrypt"]))
        self.assertEqual(candidates("$2z$10$" + "a" * 53), [])
        self.assertEqual(candidates("$wp$2z$10$" + "a" * 53), [])

    def test_sha_crypt_round_bounds(self):
        for key, marker, length in (("sha256crypt", "5", 43), ("sha512crypt", "6", 86)):
            for rounds in (1000, 999_999_999):
                self.assertTrue(validate(f"${marker}$rounds={rounds}$salt$" + "a" * length, FORMATS[key]))
            for rounds in (0, 999, 1_000_000_000):
                self.assertFalse(validate(f"${marker}$rounds={rounds}$salt$" + "a" * length, FORMATS[key]))
            self.assertFalse(validate(f"${marker}$" + "s" * 17 + "$" + "a" * length, FORMATS[key]))

    def test_salt_preserved_and_ambiguous(self):
        for digest_key, length in (("md5", 32), ("sha1", 40), ("sha256", 64), ("sha512", 128)):
            value = "A" * length + ":  Salt /$;`  "
            expected_keys = [digest_key + "-pass-salt", digest_key + "-salt-pass"]
            self.assertEqual([item.key for item in candidates(value)], expected_keys)
            self.assertEqual(normalize(value, FORMATS[expected_keys[0]], "hashcat"),
                             "a" * length + ":  Salt /$;`  ")
            with self.assertRaises(ValueError):
                normalize(value, FORMATS[expected_keys[0]], "john")
        for salt in ("", "x:y", "a" * 257, "\t", "\x1b[31m", "é"):
            self.assertEqual(candidates("a" * 32 + ":" + salt), [])

    def test_django_encoding_and_bounds(self):
        digest = base64.b64encode(hashlib.pbkdf2_hmac("sha256", b"demo", b"salt", 1000)).decode("ascii")
        value = f"pbkdf2_sha256$1000$salt${digest}"
        fmt = FORMATS["django-pbkdf2-sha256"]
        self.assertEqual(candidates(value), [fmt])
        self.assertEqual(normalize(value, fmt, "hashcat"), value)
        self.assertEqual(normalize(value, fmt, "john"), "$django$*1*" + value)
        modern = value.replace("$1000$", "$1200000$")
        self.assertTrue(validate(modern, fmt))
        with self.assertRaisesRegex(ValueError, "need John"):
            normalize(modern, fmt, "hashcat")
        for count in ("0", "-1", "2147483648", "1" * 100):
            self.assertFalse(validate(value.replace("$1000$", "$" + count + "$"), fmt))
        for salt in ("", "a" * 32, "has$delimiter", "has*delimiter", "has:delimiter"):
            self.assertFalse(validate(value.replace("$salt$", "$" + salt + "$"), fmt))
        self.assertFalse(validate(value[:-1] + "A", fmt))

    def test_bad_inputs_and_registry(self):
        for value in ("", "a" * 5000, "a" * 32 + "\n", " a" + "a" * 31,
                      "--help", "user:" + "a" * 32, "\x00" + "a" * 32):
            self.assertEqual(candidates(value), [])
        with self.assertRaises(ValueError):
            normalize("a" * 32, FORMATS["md5"], "shell")
        with self.assertRaises(ValueError):
            normalize("invalid", FORMATS["md5"], "hashcat")
        self.assertFalse(validate("a" * 32, HashFormat("md5", "fake", 1, "bogus")))


if __name__ == "__main__":
    unittest.main()
