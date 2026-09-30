#!/usr/bin/env bash
# Собирает лаунчер-стаб Aspia Host Portable (portable/launcher.c) кросс-компилятором mingw-w64.
# Стаб собирается один раз, дальше Aspia Configurator просто дописывает MSI в его хвост на каждый
# запрос (app/portable_build.py) — компилятор на каждый build не вызывается.
#
#   scripts/build-portable-stub.sh /opt/msi-rebuilder/portable
#
# Нужен пакет mingw-w64 (x86_64-w64-mingw32-gcc, x86_64-w64-mingw32-windres).
set -eu

PREFIX="${1:?usage: build-portable-stub.sh PREFIX}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$HERE/portable"
STAMP="$PREFIX/.build-stamp"

sha() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }
WANT="$(cat "$SRC_DIR/launcher.c" "$SRC_DIR/launcher.rc" "$SRC_DIR/launcher.manifest" "$SRC_DIR/aspia_host.ico" | sha | cut -d' ' -f1)"

if [ -x "$PREFIX/stub.exe" ] && [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$WANT" ]; then
  echo "portable-стаб уже собран ($PREFIX/stub.exe) — пропускаю"
  exit 0
fi

GCC="x86_64-w64-mingw32-gcc"
WINDRES="x86_64-w64-mingw32-windres"
for t in "$GCC" "$WINDRES"; do
  command -v "$t" >/dev/null || { echo "Ошибка: не найден '$t' (нужен пакет mingw-w64)" >&2; exit 1; }
done

mkdir -p "$PREFIX"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

"$WINDRES" -I "$SRC_DIR" "$SRC_DIR/launcher.rc" -O coff -o "$BUILD/launcher_res.o"
"$GCC" -O2 -municode -mwindows -DUNICODE -D_UNICODE \
  -o "$BUILD/stub.exe" "$SRC_DIR/launcher.c" "$BUILD/launcher_res.o" \
  -lshell32 -s

mv "$BUILD/stub.exe" "$PREFIX/stub.exe"
echo "$WANT" > "$STAMP"
echo "portable-стаб собран: $PREFIX/stub.exe"
