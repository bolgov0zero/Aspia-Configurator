"""Строит файл настроек Aspia Host (aspia-host.json) из полей веб-формы — без обращения к
самой программе. Реализует ровно то, что делает сам Aspia Host при экспорте/импорте настроек
и при создании пользователя (source: base/crypto/srp_math.cc, base/peer/user.cc,
base/crypto/password_hash.cc, host/settings_util.cc, github.com/dchapyshev/aspia).

Формат файла и оба криптоалгоритма подобраны так, чтобы совпадать с оригиналом побитово —
это проверено самостоятельным SRP-рукопожатием клиент/сервер в тестах (см. test_aspia_settings.py):
сгенерированная здесь пара salt/verifier проходит настоящий протокол SRP-6a, которым
пользуется хост при входе.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from typing import Dict, List, Optional, TypedDict


class SettingsError(Exception):
    """Понятная пользователю ошибка в данных формы."""


# --------------------------------------------------------------------------- SRP-8192 (пользователи)

# N — 8192-битное простое число группы SRP (RFC 5054-стиль), g — генератор.
# Значение переписано из base/crypto/srp_math.cc (kGroup_8192) без изменений;
# Сгенерировано программно из массива kGroup_8192 (не переписано вручную посимвольно —
# ручной перенос строк с пробелами уже один раз дал опечатку при разработке; см. sha256-проверку ниже).
_N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8"
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026"
    "C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AE"
    "B06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
    "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92EC"
    "F032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E"
    "59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
    "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76"
    "F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468"
    "043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
    "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED"
    "2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652D"
    "E3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
    "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6"
    "6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851D"
    "F9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
    "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA"
    "9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF"
)
# страховка от опечатки при переносе константы: если хоть один байт неверный — падаем сразу при импорте,
# а не тихо ломаем крипто для всех будущих пользователей
_N_SHA256 = "39ab4feab950a3128fb71accb9fc3965d857012e081998a85996e3ea8b3c3bcf"
if len(_N_HEX) != 2048 or hashlib.sha256(bytes.fromhex(_N_HEX)).hexdigest() != _N_SHA256:
    raise RuntimeError("srp N constant corrupted — не совпадает с эталоном из base/crypto/srp_math.cc")
N = int(_N_HEX, 16)
G = 19
SRP_GROUP = "8192"


def _blake2b512(*parts: bytes) -> bytes:
    h = hashlib.blake2b(digest_size=64)
    for p in parts:
        h.update(p)
    return h.digest()


def create_srp_user(name: str, password: str) -> Dict[str, str]:
    """salt = 64 случайных байта; x = BLAKE2b512(salt || BLAKE2b512(имя.lower() + ':' + пароль));
    verifier = g^x mod N. Копия base/peer/user.cc User::create()."""
    salt = secrets.token_bytes(64)
    inner = _blake2b512(name.lower().encode("utf-8"), b":", password.encode("utf-8"))
    x = int.from_bytes(_blake2b512(salt, inner), "big")
    v = pow(G, x, N)
    verifier = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    return {"salt": salt.hex(), "verifier": verifier.hex()}


# --------------------------------------------------------------------------- scrypt (пароль настроек)

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _SCRYPT_DKLEN, _SCRYPT_SALT_SIZE = 16384, 8, 2, 32, 256


def _scrypt(password: bytes, salt: bytes) -> bytes:
    if hasattr(hashlib, "scrypt"):
        return hashlib.scrypt(password, salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                              maxmem=64 * 1024 * 1024, dklen=_SCRYPT_DKLEN)
    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError:
        raise SettingsError("Для защиты настроек паролем на сервере нужен модуль scrypt "
                            "(python3-cryptography или Python со scrypt в hashlib)")
    return Scrypt(salt=salt, length=_SCRYPT_DKLEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P).derive(password)


def hash_settings_password(password: str) -> Dict[str, str]:
    """Copy of host/database.cc Database::setPassword(): scrypt(N=16384,r=8,p=2) -> 32 байта,
    соль — 256 случайных байт."""
    salt = secrets.token_bytes(_SCRYPT_SALT_SIZE)
    h = _scrypt(password.encode("utf-8"), salt)
    return {"password_hash": h.hex(), "password_hash_salt": salt.hex()}


# --------------------------------------------------------------------------- валидация

_USERNAME_RE = re.compile(r"^#?[A-Za-z0-9._@-]+$")


def validate_username(name: str) -> str:
    name = (name or "").strip()
    if not name or len(name) > 64:
        raise SettingsError("Имя пользователя должно быть от 1 до 64 символов")
    if not _USERNAME_RE.match(name):
        raise SettingsError("Имя «%s»: разрешены буквы, цифры и символы . _ @ -" % name)
    body = name[1:] if name.startswith("#") else name
    if not body or body.isdigit():
        raise SettingsError("Имя «%s» не может состоять только из цифр" % name)
    return name


def validate_password(password: str, field: str = "Пароль") -> str:
    if not (8 <= len(password) <= 64):
        raise SettingsError("%s должен быть от 8 до 64 символов" % field)
    return password


def validate_hex(value: str, field: str) -> str:
    value = (value or "").strip()
    if value and not re.fullmatch(r"[0-9A-Fa-f]+", value):
        raise SettingsError("%s: ожидалась hex-строка" % field)
    return value.lower()


# --------------------------------------------------------------------------- сборка users[]

class UserInput(TypedDict, total=False):
    name: str
    password: str           # пусто, если пользователь импортирован из файла и пароль не менялся
    srp_salt: str            # соль из импортированного файла — используется, только если password пуст
    srp_verifier: str        # verifier из импортированного файла — используется, только если password пуст
    sessions: int
    enabled: bool


def build_user_record(u: UserInput) -> Dict[str, object]:
    name = validate_username(u["name"])
    password = u.get("password") or ""
    if password:
        # новый пользователь или пароль сознательно сменили — считаем SRP-запись заново
        srp = create_srp_user(name, password)
        salt, verifier = srp["salt"], srp["verifier"]
    else:
        # пользователь импортирован из файла и не менялся — переносим его готовую SRP-запись как есть,
        # без пароля (расшифровать verifier обратно в пароль невозможно, да и не нужно)
        salt = validate_hex(u.get("srp_salt", ""), "Соль пользователя «%s»" % name)
        verifier = validate_hex(u.get("srp_verifier", ""), "SRP-verifier пользователя «%s»" % name)
        if not salt or not verifier:
            raise SettingsError("У пользователя «%s» не задан пароль" % name)
    sessions = int(u["sessions"]) & 63   # SESSION_TYPE_ALL = 63 (proto/peer.proto)
    if sessions == 0:
        raise SettingsError("У пользователя «%s» не выбрано ни одного разрешённого типа сессий" % name)
    return {
        "name": name,
        "group": SRP_GROUP,
        "salt": salt,
        "verifier": verifier,
        "sessions": sessions,
        "flags": 1 if u["enabled"] else 0,
    }


# --------------------------------------------------------------------------- значения по умолчанию

# Ровно то, что вернут геттеры Database/SystemSettings, когда в программе ничего не настраивали
# (host/database.cc, host/system_settings.cc). Свериться с этими числами, а не с примером файла —
# в чьём-то экспорте настройки уже могли быть изменены.
DB_DEFAULTS = {
    "tcp_port": 8050,                       # kDefaultHostTcpPort
    "router_enabled": False,
    "router_address": "",
    "router_public_key": "",
    "connect_confirmation": False,
    "no_user_action": 0,                    # NoUserAction::ACCEPT
    "auto_confirmation_interval": 0,        # мс; максимум по коду — 60000
    "one_time_password": True,
    "one_time_password_expire": 5 * 60 * 1000,      # мс; максимум по коду — 12 часов
    "one_time_password_length": 8,                   # диапазон по коду — 8..16
    "one_time_password_characters": 7,       # DIGITS|LOWER_CASE|UPPER_CASE
}
SYSTEM_DEFAULTS = {
    "update_channel": "stable",
    "preferred_video_capturer": 0,          # ScreenCapturer::Type::UNKNOWN
    "hardware_video_encoding_enabled": True,
    "application_shutdown_disabled": False,
    "auto_update_enabled": True,
    "update_check_frequency": 7,            # дней
}


# --------------------------------------------------------------------------- сборка всего файла

def build_settings_json(*, general: dict, updates: dict, confirm: dict, otp: dict,
                        router: dict, security: Optional[dict], misc: dict,
                        users: List[UserInput], require_users: bool = True) -> dict:
    """Собирает словарь для экспорта Aspia Host (host/settings_util.cc), но пишет в него только
    то, что реально отличается от значений по умолчанию самой программы — остальное и так стоит
    правильно сразу после установки, дублировать нечего. У пользователя без password (импортирован
    из файла и не менялся) должны быть заданы srp_salt/srp_verifier — его SRP-запись переносится
    как есть. require_users=False снимает требование «хотя бы один» — нужно для Portable, где
    подключение может идти через одноразовый пароль без именованной учётной записи."""
    if require_users and not users:
        raise SettingsError("Нужен хотя бы один пользователь — иначе подключиться будет некому")

    seen = set()
    user_records = []
    for u in users:
        rec = build_user_record(u)
        key = rec["name"].lower()
        if key in seen:
            raise SettingsError("Пользователь «%s» указан больше одного раза" % rec["name"])
        seen.add(key)
        user_records.append(rec)

    router_address = (router["address"] or "").strip()
    router_public_key = validate_hex(router["public_key"], "Публичный ключ маршрутизатора")
    if router["enabled"] and not router_address:
        raise SettingsError("Включён маршрутизатор, но не указан адрес")
    if router["enabled"] and not router_public_key:
        raise SettingsError("Включён маршрутизатор, но не указан публичный ключ")

    full_db = {
        "tcp_port": int(general["port"]),
        "router_enabled": bool(router["enabled"]),
        "router_address": router_address,
        "router_public_key": router_public_key,
        "connect_confirmation": bool(confirm["require"]),
        "no_user_action": int(confirm["no_user_action"]),
        "auto_confirmation_interval": min(int(confirm["auto_interval_sec"]) * 1000, 60 * 1000),
        "one_time_password": bool(otp["enabled"]),
        "one_time_password_expire": min(int(otp["expire_min"]) * 60 * 1000, 12 * 60 * 60 * 1000),
        "one_time_password_length": min(max(int(otp["length"]), 8), 16),
        "one_time_password_characters": int(otp["characters"]),
    }
    # только отличия от дефолта программы — совпадающее с дефолтом просто не пишем
    database = {k: v for k, v in full_db.items() if v != DB_DEFAULTS[k]}
    if user_records:
        database["users"] = user_records
    # иначе не пишем вовсе — пустой список ничем не отличается от того, что и так дефолт

    if security and security.get("enabled"):
        if security.get("from_file"):
            # защита настроек импортирована из файла и не менялась — переносим хеш как есть,
            # пересчитывать его не из чего (пароль восстановить из хеша нельзя)
            h = validate_hex(security.get("password_hash", ""), "Хеш пароля защиты настроек")
            s = validate_hex(security.get("password_hash_salt", ""), "Соль пароля защиты настроек")
            if not h or not s:
                raise SettingsError("Повреждён пароль защиты настроек из файла — введите новый")
            database["password_hash"] = h
            database["password_hash_salt"] = s
        else:
            validate_password(security["password"], "Пароль защиты настроек")
            if security["password"] != security.get("password2"):
                raise SettingsError("Пароли защиты настроек не совпадают")
            database.update(hash_settings_password(security["password"]))
    # иначе поле вообще не пишем — «не защищено» и так дефолт программы, нечего дублировать

    full_system = {
        "update_channel": updates["channel"],
        "preferred_video_capturer": int(general["video_capturer"]),
        "hardware_video_encoding_enabled": bool(general["hardware_encoding"]),
        "application_shutdown_disabled": bool(misc["disable_shutdown"]),
        "auto_update_enabled": bool(updates["auto_update"]),
        "update_check_frequency": int(updates["check_frequency_days"]),
    }
    system = {k: v for k, v in full_system.items() if v != SYSTEM_DEFAULTS[k]}

    doc = {}
    if database:
        doc["database"] = database
    if system:
        doc["system"] = system
    return doc
