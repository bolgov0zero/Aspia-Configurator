"""Тесты app/aspia_settings.py: python3 -m unittest tests/test_aspia_settings.py
Только критичное: совместимость крипто с реальным протоколом Aspia и ядро diff-логики
(в файл настроек попадает только то, что отличается от значений по умолчанию программы)."""
import hashlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "app"))
import aspia_settings as a  # noqa: E402


def _blake2b512(*parts):
    h = hashlib.blake2b(digest_size=64)
    for p in parts:
        h.update(p)
    return h.digest()


def _srp_handshake_key(name, password, salt_hex, verifier_hex):
    """Независимая от aspia_settings реализация обеих сторон SRP-6a (клиент + сервер) прямо по
    формулам из base/crypto/srp_math.cc. Возвращает (server_key, client_key)."""
    N, g, Nlen = a.N, a.G, 1024

    def pad(x):
        return x.to_bytes(Nlen, "big")

    v, salt = int(verifier_hex, 16), bytes.fromhex(salt_hex)
    k = int.from_bytes(_blake2b512(pad(N), pad(g)), "big")

    import secrets
    a_priv = secrets.randbelow(N - 2) + 2
    A = pow(g, a_priv, N)
    b_priv = secrets.randbelow(N - 2) + 2
    B = (k * v + pow(g, b_priv, N)) % N
    u = int.from_bytes(_blake2b512(pad(A), pad(B)), "big")
    assert u != 0

    server_key = pow(A * pow(v, u, N), b_priv, N)
    inner = _blake2b512(name.lower().encode("utf-8"), b":", password.encode("utf-8"))
    x = int.from_bytes(_blake2b512(salt, inner), "big")
    base = (B - k * pow(g, x, N)) % N
    client_key = pow(base, a_priv + u * x, N)
    return server_key, client_key


class CryptoTest(unittest.TestCase):
    """Самое критичное: сгенерированные здесь salt/verifier и password_hash должны реально
    работать с протоколом Aspia Host, а не просто "выглядеть похоже"."""

    def test_srp_handshake_matches_real_protocol(self):
        rec = a.create_srp_user("admin", "CorrectHorse1")
        srv, cli = _srp_handshake_key("admin", "CorrectHorse1", rec["salt"], rec["verifier"])
        self.assertEqual(srv, cli, "верный пароль должен давать совпадающие ключи клиента и сервера")

        srv2, cli2 = _srp_handshake_key("admin", "WrongPassword", rec["salt"], rec["verifier"])
        self.assertNotEqual(srv2, cli2, "неверный пароль не должен подходить")

    def test_scrypt_password_hash_is_correct_and_sensitive(self):
        rec = a.hash_settings_password("SettingsPass1")
        self.assertEqual(len(rec["password_hash"]), 64)         # 32 байта
        self.assertEqual(len(rec["password_hash_salt"]), 512)   # 256 байт
        # тот же пароль и соль -> тот же хэш; другой пароль -> другой хэш (иначе защита бесполезна)
        salt = bytes.fromhex(rec["password_hash_salt"])
        self.assertEqual(a._scrypt(b"SettingsPass1", salt).hex(), rec["password_hash"])
        self.assertNotEqual(a._scrypt(b"WrongPass", salt).hex(), rec["password_hash"])


class ValidationTest(unittest.TestCase):
    def test_username_validation(self):
        for n in ("admin", "user.name", "user@domain", "#123abc"):
            self.assertEqual(a.validate_username(n), n)
        for n in ("", "user name", "12345", "#123", "x" * 65):
            with self.assertRaises(a.SettingsError, msg=n):
                a.validate_username(n)

    def test_password_length(self):
        a.validate_password("12345678")   # ровно 8 — ок
        with self.assertRaises(a.SettingsError):
            a.validate_password("short1")


def _sample_users():
    return [
        {"name": "admin", "password": "AdminPass1", "sessions": 63, "enabled": True},
        {"name": "support", "password": "SupportPass1", "sessions": 21, "enabled": True},
    ]


def _default_kwargs(**overrides):
    """Все поля ровно как в свежеустановленной программе (DB_DEFAULTS/SYSTEM_DEFAULTS) —
    только это делает diff-тест ниже осмысленным."""
    base = dict(
        general={"port": 8050, "video_capturer": 0, "hardware_encoding": True},
        updates={"auto_update": True, "check_frequency_days": 7, "channel": "stable"},
        confirm={"require": False, "auto_interval_sec": 0, "no_user_action": 0},
        otp={"enabled": True, "expire_min": 5, "characters": 7, "length": 8},
        router={"enabled": False, "address": "", "public_key": ""},
        security=None,
        misc={"disable_shutdown": False},
        users=_sample_users(),
    )
    base.update(overrides)
    return base


class BuildSettingsJsonTest(unittest.TestCase):
    """Ядро фичи: в файл идёт только разница с дефолтами программы, плюс список пользователей."""

    def test_all_defaults_produce_only_users(self):
        doc = a.build_settings_json(**_default_kwargs())
        self.assertEqual(set(doc.keys()), {"database"})
        self.assertEqual(set(doc["database"].keys()), {"users"})
        self.assertEqual(len(doc["database"]["users"]), 2)
        self.assertEqual(doc["database"]["users"][0]["group"], "8192")

    def test_changed_fields_are_written(self):
        doc = a.build_settings_json(**_default_kwargs(
            general={"port": 9000, "video_capturer": 3, "hardware_encoding": True}))
        self.assertEqual(doc["database"]["tcp_port"], 9000)
        self.assertEqual(doc["system"], {"preferred_video_capturer": 3})

    def test_requires_at_least_one_user(self):
        with self.assertRaises(a.SettingsError):
            a.build_settings_json(**_default_kwargs(users=[]))

    def test_require_users_false_allows_empty_list(self):
        # Portable: подключение может идти по одноразовому паролю, именованный пользователь не нужен
        doc = a.build_settings_json(**_default_kwargs(users=[], require_users=False))
        self.assertNotIn("users", doc.get("database", {}))

    def test_user_validation_guards(self):
        dup = [{"name": "admin", "password": "AdminPass1", "sessions": 1, "enabled": True},
               {"name": "Admin", "password": "Other12345", "sessions": 1, "enabled": True}]
        with self.assertRaises(a.SettingsError):
            a.build_settings_json(**_default_kwargs(users=dup))
        no_sessions = [{"name": "admin", "password": "AdminPass1", "sessions": 0, "enabled": True}]
        with self.assertRaises(a.SettingsError):
            a.build_settings_json(**_default_kwargs(users=no_sessions))

    def test_router_enabled_requires_address_and_key(self):
        with self.assertRaises(a.SettingsError):
            a.build_settings_json(**_default_kwargs(router={"enabled": True, "address": "", "public_key": "ab"}))
        with self.assertRaises(a.SettingsError):
            a.build_settings_json(**_default_kwargs(router={"enabled": True, "address": "x", "public_key": ""}))

    def test_security_password_mismatch_rejected(self):
        sec = {"enabled": True, "password": "SettingsPass1", "password2": "Different1"}
        with self.assertRaises(a.SettingsError):
            a.build_settings_json(**_default_kwargs(security=sec))

    def test_value_caps_enforced(self):
        doc = a.build_settings_json(**_default_kwargs(
            confirm={"require": True, "auto_interval_sec": 9999, "no_user_action": 0},
            otp={"enabled": True, "expire_min": 999999, "characters": 7, "length": 999}))
        self.assertEqual(doc["database"]["auto_confirmation_interval"], 60 * 1000)
        self.assertEqual(doc["database"]["one_time_password_expire"], 12 * 60 * 60 * 1000)
        self.assertEqual(doc["database"]["one_time_password_length"], 16)

    def test_json_roundtrip(self):
        import json
        doc = a.build_settings_json(**_default_kwargs(router={"enabled": True, "address": "r.example.com", "public_key": "ab" * 32}))
        self.assertEqual(json.loads(json.dumps(doc, ensure_ascii=False)), doc)
        for k in ("name", "group", "salt", "verifier", "sessions", "flags"):
            self.assertIn(k, doc["database"]["users"][0], k)


class ImportFromFileTest(unittest.TestCase):
    """«Единая форма»: пользователь и пароль защиты настроек, импортированные из файла и не
    изменённые, переносятся как есть — без пароля, которого у нас всё равно нет."""

    def test_user_without_password_keeps_srp_from_file(self):
        srp = a.create_srp_user("admin", "OriginalPass1")
        users = [{"name": "admin", "password": "", "srp_salt": srp["salt"], "srp_verifier": srp["verifier"],
                  "sessions": 63, "enabled": True}]
        doc = a.build_settings_json(**_default_kwargs(users=users))
        rec = doc["database"]["users"][0]
        self.assertEqual(rec["salt"], srp["salt"])
        self.assertEqual(rec["verifier"], srp["verifier"])

    def test_user_without_password_or_srp_rejected(self):
        users = [{"name": "admin", "password": "", "sessions": 63, "enabled": True}]
        with self.assertRaises(a.SettingsError):
            a.build_settings_json(**_default_kwargs(users=users))

    def test_security_from_file_passthrough(self):
        h = a.hash_settings_password("OldSettingsPass1")
        sec = {"enabled": True, "from_file": True,
               "password_hash": h["password_hash"], "password_hash_salt": h["password_hash_salt"]}
        doc = a.build_settings_json(**_default_kwargs(security=sec))
        self.assertEqual(doc["database"]["password_hash"], h["password_hash"])
        self.assertEqual(doc["database"]["password_hash_salt"], h["password_hash_salt"])

    def test_security_from_file_without_hash_rejected(self):
        sec = {"enabled": True, "from_file": True, "password_hash": "", "password_hash_salt": ""}
        with self.assertRaises(a.SettingsError):
            a.build_settings_json(**_default_kwargs(security=sec))


if __name__ == "__main__":
    unittest.main()
