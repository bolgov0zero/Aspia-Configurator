"""Собирает «Aspia Host Portable.exe» — один файл, внутри которого лежит уже готовый MSI-пакет.

Компилятор (mingw-w64) на каждый запрос не вызывается: лаунчер-стаб (portable/launcher.c)
собирается один раз при установке сервиса (scripts/build-portable-stub.sh, см. install.sh) и
переиспользуется — на каждый запрос мы просто дописываем MSI в его хвост, как это делают 7z SFX
и подобные самораспаковывающиеся архивы.

Формат хвоста (см. portable/launcher.c): [8 байт длины MSI, little-endian][8 байт магии "ASPIAPX1"].
"""
from __future__ import annotations

import struct
from pathlib import Path

MAGIC = b"ASPIAPX1"


class PortableBuildError(Exception):
    """Понятная пользователю ошибка сборки portable-варианта."""


def build_portable_exe(stub_path: Path, msi_path: Path, dest_path: Path) -> None:
    """Дописывает MSI из msi_path в хвост stub_path и сохраняет результат в dest_path."""
    if not stub_path.is_file():
        raise PortableBuildError(
            "Portable-сборка недоступна: лаунчер не собран на сервере "
            "(нужен mingw-w64, см. install.sh)")

    msi_size = msi_path.stat().st_size
    trailer = struct.pack("<Q", msi_size) + MAGIC

    with open(dest_path, "wb") as out:
        with open(stub_path, "rb") as stub:
            while True:
                chunk = stub.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
        with open(msi_path, "rb") as msi:
            while True:
                chunk = msi.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
        out.write(trailer)
