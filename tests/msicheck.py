"""Проверки целостности MSI на уровне потоков (нужны утилиты gsf и msiinfo)."""
import hashlib
import os
import re
import struct
import subprocess

_A = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"


def _enc(name):
    """Имя таблицы -> имя потока в MSI (сжатое кодирование Windows Installer)."""
    out, i = chr(0x4840), 0
    while i < len(name):
        if i + 1 < len(name):
            out += chr(0x3800 + _A.index(name[i]) + (_A.index(name[i + 1]) << 6)); i += 2
        else:
            out += chr(0x4800 + _A.index(name[i])); i += 1
    return out


def _cat(msi, stream):
    return subprocess.run(["gsf", "cat", msi, stream], capture_output=True).stdout


def string_ids(msi):
    """Строка -> её ID в пуле строк."""
    sp, sd = _cat(msi, _enc("_StringPool")), _cat(msi, _enc("_StringData"))
    i, off, k, ids = 4, 0, 1, {}
    while i < len(sp):
        ln, rc = struct.unpack("<HH", sp[i:i + 4]); i += 4
        if ln == 0 and rc != 0:                 # строка длиннее 64 КБ
            ln2, _ = struct.unpack("<HH", sp[i:i + 4]); i += 4
            ln = (rc << 16) | ln2
        s = sd[off:off + ln].decode("cp1252", "replace"); off += ln
        if (ln or rc) and s not in ids:
            ids[s] = k
        k += 1
    return ids


def unsorted_tables(msi, msiinfo="msiinfo", env=None):
    """Таблицы, строки которых не упорядочены по первичному ключу (Windows Installer этого не терпит)."""
    ids = string_ids(msi)
    bad = []
    tables = subprocess.run([msiinfo, "tables", msi], capture_output=True, env=env).stdout.decode().split()
    for t in tables:
        if t.startswith("_"):
            continue
        raw = [l.rstrip("\r") for l in subprocess.run([msiinfo, "export", msi, t], capture_output=True, env=env)
               .stdout.decode("utf-8", "replace").split("\n")]
        if len(raw) < 4:
            continue
        cols, pk = raw[0].split("\t"), raw[2].split("\t")[1:]
        rows = [r.split("\t") for r in raw[3:] if r.strip()]
        rows = [r for r in rows if len(r) == len(cols)]      # многострочные значения пропускаем
        idx = [cols.index(c) for c in pk]
        seq = [[int(r[i]) if re.fullmatch(r"-?\d+", r[i]) else ids.get(r[i], 0) for i in idx] for r in rows]
        if seq != sorted(seq):
            bad.append(t)
    return bad
