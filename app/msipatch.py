"""Вшивает файл в MSI-пакет Aspia Host и перенаправляет на него штатный импорт настроек.

Пакеты Aspia Host уже содержат готовый, авторский custom action ImportSettings:

    aspia_host.exe --import="[SourceDir]aspia-host.json" --silent

Этот модуль ничего не придумывает заново — он только:
  * кладёт загруженный файл в TempFolder отдельным компонентом (в те же функции/Feature,
    что и сам aspia_host.exe — то есть ставится ровно тогда, когда ставится и сам хост);
  * правит Target существующей строки ImportSettings так, чтобы путь в кавычках указывал
    на этот файл в Temp вместо исходного (--import="[TempFolder]<имя>"), не трогая ни Type,
    ни остальную часть команды;
  * по желанию добавляет штатную строку RemoveFile для этого файла;
  * цифровую подпись удаляет (после правки она всё равно недействительна); PackageCode по
    умолчанию НЕ меняется.

Если в пакете нет ImportSettings в ожидаемом виде — отказывается: это средство только для
пакетов Aspia Host, а не общий способ вписать в любой MSI запуск произвольной команды.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import subprocess
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
TOOL_TIMEOUT = 600


class MsiError(Exception):
    """Понятная пользователю ошибка обработки пакета."""


# --------------------------------------------------------------------------- утилиты

def _tool_env() -> Optional[Dict[str, str]]:
    """Окружение для утилит msitools: если задан MSIRB_MSITOOLS_DIR, подцепляем его библиотеки."""
    d = os.environ.get("MSIRB_MSITOOLS_DIR")
    if not d:
        return None
    env = dict(os.environ)
    lib = os.path.join(d, "lib")
    for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        env[var] = lib + (os.pathsep + env[var] if env.get(var) else "")
    return env


def _tool(name: str) -> str:
    """msibuild/msiinfo берём из MSIRB_MSITOOLS_DIR (пропатченная сборка), иначе из PATH."""
    d = os.environ.get("MSIRB_MSITOOLS_DIR")
    if d and name in ("msibuild", "msiinfo"):
        path = os.path.join(d, "bin", name)
        if os.path.isfile(path):
            return path
    return name


_STORAGE_HINT = (" — это известная ошибка штатного msitools при пересохранении MSI со вложенными storages "
                 "(языковые transforms). Нужна пропатченная сборка msitools: запустите install.sh заново "
                 "(он соберёт её в /opt/msi-rebuilder/msitools)")


def _run(cmd: Sequence[str], cwd: Optional[str] = None) -> bytes:
    cmd = [_tool(cmd[0])] + list(cmd[1:])
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=TOOL_TIMEOUT, env=_tool_env())
    except FileNotFoundError:
        raise MsiError("На сервере не найдена утилита %s (пакеты msitools/gcab)" % cmd[0])
    except subprocess.TimeoutExpired:
        raise MsiError("Превышено время выполнения %s" % cmd[0])
    if p.returncode != 0:
        msg = (p.stderr or p.stdout).decode("utf-8", "replace").strip()
        if "failed to save storages" in msg or "already wrapped" in msg:
            msg += _STORAGE_HINT
        raise MsiError("%s: %s" % (os.path.basename(cmd[0]), msg or "код возврата %d" % p.returncode))
    return p.stdout


def is_ole_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(8) == OLE_MAGIC
    except OSError:
        return False


def _export_table(msi: str, table: str) -> Optional[List[Dict[str, str]]]:
    """Строки таблицы как список словарей; None, если таблицы нет."""
    try:
        out = _run(["msiinfo", "export", msi, table])
    except MsiError:
        return None
    lines = [l.rstrip("\r") for l in out.decode("utf-8", "replace").split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    if len(lines) < 3:
        return []
    cols = lines[0].split("\t")
    return [dict(zip(cols, l.split("\t"))) for l in lines[3:]]


def _list_tables(msi: str) -> List[str]:
    return _run(["msiinfo", "tables", msi]).decode("utf-8", "replace").split()


def _list_streams(msi: str) -> List[str]:
    return [l.rstrip("\r") for l in _run(["msiinfo", "streams", msi]).decode("utf-8", "replace").split("\n") if l.strip()]


# --------------------------------------------------------------------------- имена файлов

_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {"COM%d" % i for i in range(1, 10)} | {"LPT%d" % i for i in range(1, 10)}
_NAME_OK = re.compile(r"^[A-Za-z0-9 ._()+,@#&!-]+$")
_DOS_OK = re.compile(r"^[A-Za-z0-9_-]{1,8}(\.[A-Za-z0-9_-]{1,3})?$")


def validate_win_name(name: str) -> str:
    """Проверяет имя файла для Windows. Латиница, цифры и безопасные символы."""
    name = (name or "").strip()
    if not name:
        raise MsiError("Пустое имя файла")
    if len(name) > 200:
        raise MsiError("Слишком длинное имя файла")
    if not name.isascii():
        raise MsiError("Имя файла «%s» содержит не-ASCII символы — задайте имя латиницей" % name)
    if not _NAME_OK.match(name):
        raise MsiError("Имя «%s» содержит недопустимые символы (разрешены буквы, цифры, пробел и . _ - ( ) + , @ # & !)" % name)
    if name != name.rstrip(". "):
        raise MsiError("Имя не должно заканчиваться точкой или пробелом")
    if name.split(".")[0].upper() in _RESERVED:
        raise MsiError("«%s» — зарезервированное имя Windows" % name)
    if name in (".", ".."):
        raise MsiError("Недопустимое имя")
    return name


def dos_name(name: str) -> str:
    """Формат 'SHORT~1.EXT|Long name.ext' для колонки FileName."""
    if _DOS_OK.match(name):
        return name
    base, dot, ext = name.rpartition(".")
    if not dot:
        base, ext = name, ""
    short = re.sub(r"[^A-Za-z0-9]", "", base).upper()[:6] or "FILE"
    ext = re.sub(r"[^A-Za-z0-9]", "", ext).upper()[:3]
    return "%s~1%s|%s" % (short, "." + ext if ext else "", name)


def _long_name(field_value: str) -> str:
    """Из 'target:source' и 'short|long' берёт длинное имя целевого каталога/файла."""
    t = field_value.split(":", 1)[0]
    return t.split("|", 1)[1] if "|" in t else t


# --------------------------------------------------------------------------- описание пакета

def describe(msi: str) -> Dict[str, object]:
    """Краткие сведения о пакете для интерфейса."""
    if not is_ole_file(msi):
        raise MsiError("Файл не является MSI-пакетом (неверная сигнатура)")
    props = _export_table(msi, "Property")
    if props is None:
        raise MsiError("Не удалось прочитать таблицу Property — это точно MSI?")
    pmap = {r["Property"]: r["Value"] for r in props}
    summary = {r["PropertyId"]: r["Value"] for r in (_export_table(msi, "_SummaryInformation") or [])}
    template = summary.get("7", "")
    streams = [s.lstrip("\x05") for s in _list_streams(msi)]
    ca = {r["Action"]: r for r in (_export_table(msi, "CustomAction") or [])}
    imp = ca.get(IMPORT_ACTION, {})
    return {
        "product": pmap.get("ProductName", ""),
        "version": pmap.get("ProductVersion", ""),
        "arch": "x64" if re.search(r"x64|amd64|intel64", template, re.I) else ("arm64" if re.search(r"arm64", template, re.I) else "x86"),
        "signed": any(s in ("DigitalSignature", "MsiDigitalSignatureEx") for s in streams),
        "importable": bool(_IMPORT_TARGET_RE.search(imp.get("Target") or "")),
    }


# --------------------------------------------------------------------------- SQL

def _sql_val(v: object) -> str:
    if isinstance(v, int):
        return str(v)
    s = str(v)
    if "'" in s or "\x00" in s:
        raise MsiError("Недопустимый символ в значении %r" % s)
    return "'%s'" % s


def _insert(table: str, **cols: object) -> str:
    names = ",".join("`%s`" % c for c in cols)
    vals = ",".join(_sql_val(v) for v in cols.values())
    return "INSERT INTO `%s` (%s) VALUES (%s)" % (table, names, vals)


def _new_guid() -> str:
    return "{%s}" % str(uuid.uuid4()).upper()


# --------------------------------------------------------------------------- основная операция

IMPORT_ACTION = "ImportSettings"                                     # штатный custom action пакетов Aspia Host
_IMPORT_TARGET_RE = re.compile(r'--import="\[([A-Za-z0-9_]+)\]([^"]*)"')


@dataclass
class Result:
    temp_path: str                 # куда ляжет файл на целевой машине (для показа пользователю)
    command: str                    # итоговая команда ImportSettings после правки
    cleanup: Optional[str]          # как и когда убирается файл, если delete_after
    package_code: Optional[str]
    signature_removed: bool


def add_import_file(src_msi: str, dst_msi: str, payload: str, filename: str, workdir: str,
                    delete_after: bool = True, new_package_code: bool = False) -> Result:
    """Копирует src_msi в dst_msi, вшивает payload в TempFolder и перенаправляет на него
    штатный ImportSettings. Требует, чтобы такой custom action уже был в пакете в ожидаемом виде."""
    filename = validate_win_name(filename)
    size = os.path.getsize(payload)
    if size <= 0:
        raise MsiError("Файл пустой")
    if size >= 2 ** 31 - 1:
        raise MsiError("Файл слишком большой для MSI (лимит 2 ГБ)")

    if not is_ole_file(src_msi):
        raise MsiError("Исходный файл не является MSI-пакетом")
    info = describe(src_msi)

    tables = _list_tables(src_msi)
    for need in ("Directory", "Component", "File", "Media", "FeatureComponents", "CustomAction"):
        if need not in tables:
            raise MsiError("В пакете нет таблицы %s — нестандартный MSI" % need)

    dirs = {r["Directory"]: r for r in (_export_table(src_msi, "Directory") or [])}
    comps = {r["Component"]: r for r in (_export_table(src_msi, "Component") or [])}
    files = _export_table(src_msi, "File") or []
    media = _export_table(src_msi, "Media") or []
    cas = {r["Action"]: r for r in (_export_table(src_msi, "CustomAction") or [])}
    feat_comps = _export_table(src_msi, "FeatureComponents") or []

    ca = cas.get(IMPORT_ACTION)
    if ca is None:
        raise MsiError("В пакете нет штатного действия «%s» — этот сервис подходит только для "
                       "пакетов Aspia Host, где оно уже есть" % IMPORT_ACTION)
    tm = _IMPORT_TARGET_RE.search(ca.get("Target") or "")
    if not tm:
        raise MsiError("Команда действия «%s» имеет неожиданный вид (%r) — автоматическая правка "
                       "небезопасна, нужна ручная проверка" % (IMPORT_ACTION, ca.get("Target")))

    exe_file = next((f for f in files if f["File"] == ca.get("Source")), None)
    if exe_file is None:
        raise MsiError("Не найден файл, который запускает действие «%s»" % IMPORT_ACTION)
    # функции (Feature), в которые входит компонент с этим exe — наш файл ставим в те же,
    # чтобы он появлялся ровно тогда, когда ставится и сам aspia_host.exe
    target_features = sorted({r["Feature_"] for r in feat_comps if r["Component_"] == exe_file["Component_"]})
    if not target_features:
        raise MsiError("Не удалось определить функцию (Feature) для «%s»" % IMPORT_ACTION)

    rid = uuid.uuid4().hex[:8].upper()
    sql: List[str] = []

    # каталог TempFolder
    if "TempFolder" not in dirs:
        if "TARGETDIR" not in dirs:
            raise MsiError("В таблице Directory нет TARGETDIR — нестандартный MSI")
        sql.append(_insert("Directory", Directory="TempFolder", Directory_Parent="TARGETDIR", DefaultDir="."))

    # такой файл уже устанавливается в Temp?
    for f in files:
        c = comps.get(f["Component_"])
        if c and c["Directory_"] == "TempFolder" and _long_name(f["FileName"]).lower() == filename.lower():
            raise MsiError("В пакете уже есть файл «%s», устанавливаемый в Temp" % filename)

    file_key = "RBF_%s" % rid
    comp_key = "RBC_%s" % rid
    cab_name = "rb%s.cab" % rid.lower()

    # последовательность и носитель
    max_seq = max([int(f["Sequence"] or 0) for f in files] + [0])
    max_last = max([int(m["LastSequence"] or 0) for m in media] + [0])
    max_disk = max([int(m["DiskId"] or 0) for m in media] + [0])
    seq = max(max_seq, max_last) + 1
    disk = max_disk + 1

    win64 = 256 if info["arch"] in ("x64", "arm64") else 0
    sql.append(_insert("Component", Component=comp_key, ComponentId=_new_guid(), Directory_="TempFolder",
                       Attributes=win64, Condition="", KeyPath=file_key))
    for feat in target_features:
        sql.append(_insert("FeatureComponents", Feature_=feat, Component_=comp_key))
    # 512 = vital, 16384 = сжат в cab
    sql.append(_insert("File", File=file_key, Component_=comp_key, FileName=dos_name(filename), FileSize=size,
                       Version="", Language="", Attributes=512 | 16384, Sequence=seq))

    md5 = hashlib.md5()
    with open(payload, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            md5.update(chunk)
    h = struct.unpack("<4i", md5.digest())
    if "MsiFileHash" not in tables:
        sql.append("CREATE TABLE `MsiFileHash` (`File_` CHAR(72) NOT NULL, `Options` INT NOT NULL, "
                   "`HashPart1` LONG NOT NULL, `HashPart2` LONG NOT NULL, `HashPart3` LONG NOT NULL, "
                   "`HashPart4` LONG NOT NULL PRIMARY KEY `File_`)")
    sql.append(_insert("MsiFileHash", File_=file_key, Options=0, HashPart1=h[0], HashPart2=h[1], HashPart3=h[2], HashPart4=h[3]))
    sql.append(_insert("Media", DiskId=disk, LastSequence=seq, DiskPrompt="", Cabinet="#" + cab_name, VolumeLabel="", Source=""))

    # перенаправляем штатный ImportSettings на наш файл: меняем только путь в кавычках,
    # Type и остальную часть команды не трогаем
    new_target = ca["Target"][:tm.start()] + '--import="[TempFolder]%s"' % filename + ca["Target"][tm.end():]
    sql.append("UPDATE `CustomAction` SET `Target`=%s WHERE `Action`=%s" % (_sql_val(new_target), _sql_val(IMPORT_ACTION)))

    cleanup_desc: Optional[str] = None
    if delete_after:
        if "RemoveFile" not in tables:
            raise MsiError("В пакете нет таблицы RemoveFile — штатное удаление недоступно")
        sql.append(_insert("RemoveFile", FileKey=file_key, Component_=comp_key, FileName=dos_name(filename),
                           DirProperty="TempFolder", InstallMode=3))
        cleanup_desc = ("файл удаляется штатным действием RemoveFile при удалении программы и перед "
                        "установкой новой копии поверх старой. Сразу после самого импорта в этой же "
                        "установке файл не удаляется — по порядку установки RemoveFiles выполняется "
                        "раньше ImportSettings")

    # cab-архив: имя файла внутри = ключ в таблице File
    cabdir = os.path.join(workdir, "cab")
    os.makedirs(cabdir, exist_ok=True)
    shutil.copyfile(payload, os.path.join(cabdir, file_key))
    _run(["gcab", "-c", "-n", cab_name, file_key], cwd=cabdir)
    cab_path = os.path.join(cabdir, cab_name)
    if not os.path.isfile(cab_path):
        raise MsiError("gcab не создал cab-архив")

    # подпись: после правки недействительна — удаляем
    sig_streams = [s for s in _list_streams(src_msi) if s.lstrip("\x05") in ("DigitalSignature", "MsiDigitalSignatureEx")]
    for s in sig_streams:
        sql.append("DELETE FROM `_Streams` WHERE `Name`='%s'" % s)

    # новый PackageCode (Revision number в SummaryInformation) — только по запросу
    package_code: Optional[str] = None
    si_path: Optional[str] = None
    if new_package_code:
        package_code = _new_guid()
        si_path = os.path.join(workdir, "_SummaryInformation.idt")
        si_raw = _run(["msiinfo", "export", src_msi, "_SummaryInformation"]).decode("utf-8", "surrogateescape")
        lines = si_raw.split("\n")
        replaced = False
        for i in range(3, len(lines)):
            if lines[i].startswith("9\t"):
                lines[i] = "9\t" + package_code + ("\r" if lines[i].endswith("\r") else "")
                replaced = True
        if not replaced:
            raise MsiError("В пакете нет свойства Revision number (PackageCode)")
        with open(si_path, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
            f.write("\n".join(lines))

    # применяем всё к копии
    shutil.copyfile(src_msi, dst_msi)
    cmd = ["msibuild", dst_msi]
    for s in sql:
        cmd += ["-q", s]
    cmd += ["-a", cab_name, cab_path]
    if si_path:
        cmd += ["-i", si_path]
    try:
        _run(cmd)
        _verify(dst_msi, file_key, cab_name, package_code, new_target)
    except Exception:
        if os.path.exists(dst_msi):
            os.remove(dst_msi)
        raise

    return Result(
        temp_path="%TEMP%\\" + filename,
        command=new_target,
        cleanup=cleanup_desc,
        package_code=package_code,
        signature_removed=bool(sig_streams),
    )


def _verify(msi: str, file_key: str, cab_name: str, package_code: Optional[str], expected_target: str) -> None:
    """Пост-проверка: строки на месте, cab встроен, ImportSettings указывает на новый файл, PackageCode обновлён."""
    if not any(r["File"] == file_key for r in (_export_table(msi, "File") or [])):
        raise MsiError("Проверка: строка File не добавлена")
    if not any(r["Cabinet"] == "#" + cab_name for r in (_export_table(msi, "Media") or [])):
        raise MsiError("Проверка: строка Media не добавлена")
    if cab_name not in _list_streams(msi):
        raise MsiError("Проверка: cab-архив не встроен в пакет")
    ca = {r["Action"]: r for r in (_export_table(msi, "CustomAction") or [])}
    if ca.get(IMPORT_ACTION, {}).get("Target") != expected_target:
        raise MsiError("Проверка: команда %s не обновлена" % IMPORT_ACTION)
    if package_code:
        si = {r["PropertyId"]: r["Value"] for r in (_export_table(msi, "_SummaryInformation") or [])}
        if si.get("9") != package_code:
            raise MsiError("Проверка: PackageCode не обновлён")
    describe(msi)
