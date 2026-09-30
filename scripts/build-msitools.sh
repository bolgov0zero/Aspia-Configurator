#!/usr/bin/env bash
# Собирает msitools 0.106 с исправлениями libmsi (vendor/msitools-storage-fixes.patch) и ставит в PREFIX.
# Штатный msibuild портит MSI со вложенными storages (встроенные языковые transforms, как у Aspia):
#   1) падает с "Attempt to wrap an output that is already wrapped / failed to save storages";
#   2) теряет CLSID у storages — Windows Installer тогда выдаёт "Ошибка применения преобразований" (1624);
#   3) пишет строки таблиц не по порядку ключа — Windows Installer: ошибка 2211 ("Could not create database table").
#
#   scripts/build-msitools.sh /opt/msi-rebuilder/msitools
#
# Нужны: ninja gcc bison perl valac gettext patch pkg-config python3, dev-пакеты glib, libgsf, libgcab, libxml2.
# meson нужен версии >= 1.4 (msitools этого требует); если системный старше (как в Debian 13 — там 1.0.1),
# скрипт сам ставит свежий meson в отдельное venv рядом с PREFIX — систему это не трогает.
set -eu

PREFIX="${1:?usage: build-msitools.sh PREFIX}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARBALL="$HERE/vendor/msitools-0.106.tar.xz"
PATCH="$HERE/vendor/msitools-storage-fixes.patch"
STAMP="$PREFIX/.build-stamp"
MIN_MESON="1.4.0"

sha() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }
WANT="$(cat "$TARBALL" "$PATCH" | sha | cut -d' ' -f1)"

if [ -x "$PREFIX/bin/msibuild" ] && [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$WANT" ]; then
  echo "msitools уже собран ($PREFIX) — пропускаю"
  exit 0
fi

for t in ninja bison perl valac patch pkg-config python3; do
  command -v "$t" >/dev/null || { echo "Ошибка: не найден '$t' (нужен для сборки msitools)" >&2; exit 1; }
done

ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$1" ]; }   # $1 >= $2 ?

MESON=""
if command -v meson >/dev/null; then
  v="$(meson --version 2>/dev/null || echo 0)"
  ver_ge "$v" "$MIN_MESON" && MESON="$(command -v meson)"
fi
if [ -z "$MESON" ]; then
  MESONENV="${PREFIX}.mesonenv"
  if [ ! -x "$MESONENV/bin/meson" ]; then
    echo "Системный meson старее $MIN_MESON — ставлю свежий в $MESONENV (систему не трогаю)"
    rm -rf "$MESONENV"
    python3 -m venv "$MESONENV" \
      || { echo "Ошибка: не удалось создать venv для meson (нужен пакет python3-venv)" >&2; exit 1; }
    "$MESONENV/bin/pip" install --quiet --upgrade pip
    "$MESONENV/bin/pip" install --quiet "meson>=$MIN_MESON"
  fi
  MESON="$MESONENV/bin/meson"
fi

SRC="$(mktemp -d)"
trap 'rm -rf "$SRC"' EXIT
tar -xJf "$TARBALL" -C "$SRC"
cd "$SRC/msitools-0.106"
patch -p1 < "$PATCH"
"$MESON" setup build -Dintrospection=false --buildtype=release --prefix="$PREFIX" --libdir=lib
"$MESON" compile -C build
mkdir -p "$PREFIX"
"$MESON" install -C build
echo "$WANT" > "$STAMP"
echo "msitools собран и установлен в $PREFIX"
