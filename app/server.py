"""Веб-интерфейс сервиса пересборки MSI-пакетов Aspia Host: вшивает файл настроек и
перенаправляет на него штатный импорт (ImportSettings) пакета.

Полностью без состояния: и исходный MSI-пакет, и файл настроек загружаются вместе, за одно
действие, обрабатываются во временном каталоге и сразу отдаются в ответ на запрос — после чего
временный каталог удаляется. На сервере не остаётся ни списка пакетов, ни истории сборок:
перезагрузка страницы ничего не показывает, потому что сохранять нечего. Хранится только общий
счётчик числа сборок (просто число, без привязки к файлам или людям)."""
from __future__ import annotations

import hmac
import io
import json
import os
import shutil
import tempfile
import threading
import uuid
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, abort, flash, redirect, render_template, request, send_file, url_for

import aspia_settings
import github_releases
import msipatch
from aspia_settings import SettingsError
from github_releases import ReleasesError
from msipatch import MsiError

DATA_DIR = Path(os.environ.get("MSIRB_DATA_DIR", "/var/lib/msi-rebuilder"))
TMP_DIR = DATA_DIR / "tmp"
COUNTER_FILE = DATA_DIR / "build_count"   # счётчик успешных сборок; сами файлы в нём не участвуют
AUTH_USER = os.environ.get("MSIRB_USER", "admin")
AUTH_PASSWORD = os.environ.get("MSIRB_PASSWORD", "")   # пусто — доступ без пароля
MAX_UPLOAD_MB = int(os.environ.get("MSIRB_MAX_UPLOAD_MB", "1024"))

DATA_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.secret_key = os.environ.get("MSIRB_SECRET") or uuid.uuid4().hex

_counter_lock = threading.Lock()


def read_build_count() -> int:
    try:
        return int(COUNTER_FILE.read_text("utf-8").strip() or "0")
    except (OSError, ValueError):
        return 0


def bump_build_count() -> int:
    """Атомарно увеличивает счётчик собранных пакетов на 1 и возвращает новое значение."""
    with _counter_lock:
        n = read_build_count() + 1
        tmp = COUNTER_FILE.with_name(COUNTER_FILE.name + ".tmp")
        tmp.write_text(str(n), "utf-8")
        tmp.replace(COUNTER_FILE)   # атомарная замена — параллельное чтение не увидит недописанный файл
        return n


# --------------------------------------------------------------------------- защита

@app.before_request
def guard():
    if request.path == "/healthz":
        return None
    if AUTH_PASSWORD:   # если пароль не задан — сервис открыт без авторизации
        a = request.authorization
        ok = bool(a) and hmac.compare_digest((a.username or "").encode(), AUTH_USER.encode()) \
            & hmac.compare_digest((a.password or "").encode(), AUTH_PASSWORD.encode())
        if not ok:
            return Response("Требуется авторизация", 401, {"WWW-Authenticate": 'Basic realm="Aspia Configurator", charset="UTF-8"'})
    if request.method == "POST":   # лёгкая защита от межсайтовой отправки формы
        origin = request.headers.get("Origin")
        if request.headers.get("Sec-Fetch-Site") == "cross-site" or (origin and urlparse(origin).netloc != request.host):
            abort(403)
    return None


@app.errorhandler(413)
def too_large(_e):
    flash("Файл больше допустимого размера (%d МБ)" % MAX_UPLOAD_MB, "error")
    return redirect(url_for("index"))


@app.route("/healthz")
def healthz():
    return "ok"


# --------------------------------------------------------------------------- страницы

@app.route("/")
def index():
    return render_template("index.html", build_count=read_build_count(),
                           import_action=msipatch.IMPORT_ACTION, max_mb=MAX_UPLOAD_MB)


@app.route("/count")
def count():
    """Текущее значение счётчика — опрашивается со страницы, чтобы обновлять его вживую."""
    return {"count": read_build_count()}


@app.route("/releases")
def releases():
    """Версии 3.x.x Aspia Host (Windows x64) с GitHub — подставляются в выпадающий список."""
    try:
        data = github_releases.list_releases()
    except ReleasesError as e:
        return {"error": str(e)}, 502
    return {"releases": [{"version": r["version"]} for r in data]}


def _bool(field: str) -> bool:
    return request.form.get(field) not in (None, "", "0", "false")


def _int(field: str, default: int = 0) -> int:
    try:
        return int(request.form.get(field, default))
    except (TypeError, ValueError):
        raise SettingsError("Поле «%s» должно быть числом" % field)


def _settings_from_form() -> dict:
    """Собирает kwargs для aspia_settings.build_settings_json() из полей формы. Пользователи и
    пароль защиты настроек могут быть импортированы из файла и не изменены — тогда пароля нет,
    а готовая SRP-запись/хеш приходят прямо из JSON, распарсенного на клиенте."""
    try:
        users_raw = json.loads(request.form.get("users_json") or "[]")
    except ValueError:
        raise SettingsError("Список пользователей повреждён — попробуйте добавить их заново")
    if not isinstance(users_raw, list):
        raise SettingsError("Список пользователей повреждён — попробуйте добавить их заново")
    users = []
    for u in users_raw:
        if not isinstance(u, dict):
            raise SettingsError("Список пользователей повреждён — попробуйте добавить их заново")
        users.append({
            "name": str(u.get("name", "")),
            "password": str(u.get("password", "")),
            "srp_salt": str(u.get("srpSalt", "")),
            "srp_verifier": str(u.get("srpVerifier", "")),
            "sessions": int(u.get("sessions") or 0),
            "enabled": bool(u.get("enabled", True)),
        })

    security = None
    if _bool("security_enabled"):
        if _bool("security_from_file"):
            security = {
                "enabled": True,
                "from_file": True,
                "password_hash": request.form.get("security_hash", ""),
                "password_hash_salt": request.form.get("security_hash_salt", ""),
            }
        else:
            security = {
                "enabled": True,
                "password": request.form.get("security_password", ""),
                "password2": request.form.get("security_password2", ""),
            }

    return dict(
        general={
            "port": _int("port", 8050),
            "video_capturer": _int("video_capturer", 0),
            "hardware_encoding": _bool("hardware_encoding"),
        },
        updates={
            "auto_update": _bool("auto_update"),
            "check_frequency_days": _int("check_frequency_days", 7),
            "channel": request.form.get("update_channel", "stable"),
        },
        confirm={
            "require": _bool("confirm_require"),
            "auto_interval_sec": _int("confirm_auto_interval", 15),
            "no_user_action": _int("no_user_action", 1),
        },
        otp={
            "enabled": _bool("otp_enabled"),
            "expire_min": _int("otp_expire_min", 60),
            "characters": _int("otp_characters", 7),
            "length": _int("otp_length", 8),
        },
        router={
            "enabled": _bool("router_enabled"),
            "address": request.form.get("router_address", ""),
            "public_key": request.form.get("router_public_key", ""),
        },
        security=security,
        misc={"disable_shutdown": _bool("disable_shutdown")},
        users=users,
    )


@app.route("/build", methods=["POST"])
def build():
    """Собирает пакет и сразу отдаёт файл в ответ. Исходный MSI-пакет и данные формы настроек
    приходят в этом же запросе и нигде не сохраняются: рабочий каталог удаляется, как только
    собранный файл прочитан в память для отправки."""
    pkg_source = request.form.get("package_source", "upload")

    pkg_upload = None
    release = None
    if pkg_source == "release":
        release_version = (request.form.get("release_version") or "").strip()
        try:
            release = github_releases.find_release(release_version)
        except ReleasesError as e:
            flash(str(e), "error")
            return redirect(url_for("index"))
        if not release:
            flash("Версия не найдена — обновите страницу и выберите заново", "error")
            return redirect(url_for("index"))
    else:
        pkg_upload = request.files.get("package")
        if not pkg_upload or not pkg_upload.filename:
            flash("Выберите исходный MSI-пакет Aspia Host", "error")
            return redirect(url_for("index"))

    delete_after = bool(request.form.get("delete_after"))

    work = Path(tempfile.mkdtemp(dir=TMP_DIR))
    try:
        src = work / "src.msi"
        if release:
            github_releases.download_release(release, src, max_bytes=app.config["MAX_CONTENT_LENGTH"])
        else:
            pkg_upload.save(src)
        if not msipatch.is_ole_file(str(src)):
            raise MsiError("Исходный файл не является MSI-пакетом")

        payload = work / "payload"
        settings = aspia_settings.build_settings_json(**_settings_from_form())
        payload.write_text(json.dumps(settings, ensure_ascii=False), "utf-8")

        dst = work / "out.msi"
        msipatch.add_import_file(str(src), str(dst), str(payload), "aspia-host.json", str(work),
                                 delete_after=delete_after,
                                 new_package_code=bool(request.form.get("new_package_code")))
        data = dst.read_bytes()
    except (MsiError, SettingsError, ReleasesError) as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    except Exception as e:  # noqa: BLE001
        app.logger.exception("build failed")
        flash("Внутренняя ошибка: %s" % e, "error")
        return redirect(url_for("index"))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    bump_build_count()
    raw_stem = Path((release["asset_name"] if release else pkg_upload.filename).replace("\\", "/")).stem
    pkg_stem = "".join(c for c in raw_stem if c.isalnum() or c in "._-() ").strip() or "aspia-host"
    download_name = "%s_mod.msi" % pkg_stem
    return send_file(io.BytesIO(data), as_attachment=True, download_name=download_name, mimetype="application/x-msi")
