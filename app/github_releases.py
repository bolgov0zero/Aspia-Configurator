"""Список релизов 3.x.x Aspia (github.com/dchapyshev/aspia) и загрузка Windows x64 MSI-пакета
из выбранного релиза — как альтернатива ручной загрузке файла на странице.

Список кэшируется в памяти процесса на CACHE_TTL секунд (это не персистентное хранилище,
а просто снижение числа обращений к GitHub API, лимит которого — 60 запросов/час без токена)."""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

REPO_API = "https://api.github.com/repos/dchapyshev/aspia/releases"
USER_AGENT = "aspia-configurator"
CACHE_TTL = 600  # секунд

# Имя ассета для 64-битного Windows-инсталлятора host-части, например aspia-host-3.0.20-x86_64.msi
_ASSET_RE = re.compile(r"^aspia-host-\d+\.\d+\.\d+-x86_64\.msi$")
_TAG_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


class ReleasesError(Exception):
    """Понятная пользователю ошибка при обращении к GitHub."""


_cache: Dict[str, object] = {"data": None, "ts": 0.0}
_lock = threading.Lock()


def _http_get_json(url: str, timeout: int = 15):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise ReleasesError("GitHub временно отклоняет запросы (лимит API) — попробуйте позже")
        raise ReleasesError("GitHub API вернул ошибку %s" % e.code)
    except (urllib.error.URLError, OSError) as e:
        raise ReleasesError("Не удалось связаться с GitHub: %s" % e)
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        raise ReleasesError("GitHub вернул неожиданный ответ")


def _fetch_all() -> List[dict]:
    results: List[dict] = []
    page = 1
    while page <= 5:   # страховка от бесконечной пагинации; 500 релизов с запасом хватит
        try:
            items = _http_get_json(REPO_API + "?per_page=100&page=%d" % page)
        except ReleasesError:
            if results:
                break   # часть уже собрали — лучше отдать её, чем ничего
            raise
        if not items:
            break
        page_has_v3 = False
        for rel in items:
            if rel.get("draft"):
                continue
            m = _TAG_RE.match((rel.get("tag_name") or "").strip())
            if not m or int(m.group(1)) != 3:
                continue
            page_has_v3 = True
            asset = next((a for a in rel.get("assets", []) if _ASSET_RE.match(a.get("name", ""))), None)
            if not asset:
                continue
            digest = asset.get("digest") or ""
            sha256 = digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else None
            results.append({
                "version": "%s.%s.%s" % m.groups(),
                "version_key": tuple(int(x) for x in m.groups()),
                "download_url": asset["browser_download_url"],
                "asset_name": asset["name"],
                "size": asset.get("size", 0),
                "sha256": sha256,
            })
        if not page_has_v3 and results:
            break   # релизы идут от новых к старым — версии 3.x закончились
        page += 1

    seen = set()
    uniq = []
    for r in sorted(results, key=lambda r: r["version_key"], reverse=True):
        if r["version"] in seen:
            continue
        seen.add(r["version"])
        uniq.append(r)
    return uniq


def list_releases() -> List[dict]:
    """Список релизов 3.x.x с x86_64 MSI-ассетом, новые сначала. Кэшируется на CACHE_TTL секунд."""
    with _lock:
        now = time.time()
        if _cache["data"] is not None and now - _cache["ts"] < CACHE_TTL:
            return _cache["data"]
        data = _fetch_all()
        _cache["data"] = data
        _cache["ts"] = now
        return data


def find_release(version: str) -> Optional[dict]:
    version = (version or "").strip()
    for r in list_releases():
        if r["version"] == version:
            return r
    return None


def download_release(release: dict, dest_path: Path, max_bytes: int) -> None:
    """Скачивает MSI-ассет релиза в dest_path и сверяет sha256 (если GitHub его прислал)."""
    req = urllib.request.Request(release["download_url"], headers={"User-Agent": USER_AGENT})
    hasher = hashlib.sha256()
    written = 0
    try:
        with urllib.request.urlopen(req, timeout=120) as resp, open(dest_path, "wb") as f:
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise ReleasesError("Файл релиза больше допустимого размера")
                hasher.update(chunk)
                f.write(chunk)
    except urllib.error.HTTPError as e:
        raise ReleasesError("GitHub вернул ошибку %s при скачивании пакета" % e.code)
    except (urllib.error.URLError, OSError) as e:
        raise ReleasesError("Не удалось скачать пакет с GitHub: %s" % e)
    if release.get("sha256") and hasher.hexdigest() != release["sha256"]:
        raise ReleasesError("Контрольная сумма скачанного файла не совпадает — возможно, он повреждён")
