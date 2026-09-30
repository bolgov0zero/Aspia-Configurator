#!/usr/bin/env bash
# Установка Aspia Configurator на Debian/Ubuntu: зависимости, сервис systemd с автозапуском, веб-интерфейс.
#
#   sudo ./install.sh [--port 8080] [--host 0.0.0.0] [--user admin] [--password ПАРОЛЬ]
#                     [--reset-password] [--no-password]
#
# По умолчанию сервис открыт БЕЗ пароля — рассчитан на закрытую сеть/VPN с TLS снаружи (см. README).
# Чтобы включить парольную защиту, передайте --password или --reset-password (сгенерирует случайный).
# --no-password возвращает уже защищённый паролем сервис обратно к открытому доступу.
#
# Повторный запуск обновляет код и перезапускает сервис; настройки в /etc/msi-rebuilder/ сохраняются.
set -eu

APP_NAME=msi-rebuilder
APP_DIR=/opt/$APP_NAME
DATA_DIR=/var/lib/$APP_NAME
CONF_DIR=/etc/$APP_NAME
ENV_FILE=$CONF_DIR/$APP_NAME.env
UNIT_FILE=/etc/systemd/system/$APP_NAME.service
SVC_USER=msirb
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PORT="" HOST="" WEB_USER="" PASSWORD="" RESET_PASSWORD=0 NO_PASSWORD=0

die() { echo "Ошибка: $*" >&2; exit 1; }
log() { echo "==> $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --port)           PORT="${2:?}"; shift 2 ;;
    --host)           HOST="${2:?}"; shift 2 ;;
    --user)           WEB_USER="${2:?}"; shift 2 ;;
    --password)       PASSWORD="${2:?}"; shift 2 ;;
    --reset-password) RESET_PASSWORD=1; shift ;;
    --no-password)    NO_PASSWORD=1; shift ;;
    -h|--help)        sed -n '2,11p' "$0"; exit 0 ;;
    *) die "неизвестный параметр: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "запустите от root: sudo ./install.sh"
command -v apt-get >/dev/null || die "нужен Debian/Ubuntu (apt-get)"
command -v systemctl >/dev/null || die "нужен systemd"
[ -f "$SRC_DIR/app/server.py" ] || die "не найден app/server.py рядом со скриптом"
case "$PORT" in ""|*[!0-9]*) [ -z "$PORT" ] || die "порт должен быть числом" ;; esac
case "$PASSWORD$WEB_USER" in *[[:space:]\'\"\\\$\#]*) die "логин и пароль не должны содержать пробелы и символы ' \" \\ \$ #" ;; esac

# ---- зависимости
# msitools собираем из исходников с исправлением libmsi (см. vendor/), поэтому нужны инструменты сборки.
# mingw-w64 нужен для лаунчера Aspia Host Portable (portable/launcher.c) — собирается один раз, дальше
# MSI просто дописывается в его хвост на каждый запрос, компилятор при обычной работе не используется.
log "Установка пакетов (gcab, python3-flask, gunicorn, mingw-w64 + инструменты сборки msitools)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  gcab python3 python3-flask gunicorn ca-certificates \
  build-essential meson ninja-build pkg-config patch xz-utils bison perl valac gettext \
  python3-venv python3-pip python3-cryptography mingw-w64 \
  libglib2.0-dev libgsf-1-dev libgcab-dev libxml2-dev >/dev/null
command -v gcab >/dev/null || die "не удалось установить gcab"
GUNICORN="$(command -v gunicorn)" || die "gunicorn не найден после установки"

# ---- пользователь и каталоги
if ! id "$SVC_USER" >/dev/null 2>&1; then
  log "Создаю системного пользователя $SVC_USER"
  useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi
install -d -m 0755 "$APP_DIR" "$CONF_DIR"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR" "$DATA_DIR/tmp"

# ---- код приложения
log "Копирую приложение в $APP_DIR"
rm -rf "$APP_DIR/templates"
cp -R "$SRC_DIR/app/." "$APP_DIR/"
find "$APP_DIR" -name __pycache__ -prune -exec rm -rf {} \; 2>/dev/null || true
chown -R root:root "$APP_DIR"
chmod -R go-w "$APP_DIR"

# ---- msitools с исправлением (штатный msibuild не пересохраняет MSI со вложенными storages)
log "Собираю msitools с исправлением (1-2 минуты)"
"$SRC_DIR/scripts/build-msitools.sh" "$APP_DIR/msitools" >/tmp/msirb-build.log 2>&1 \
  || { tail -n 30 /tmp/msirb-build.log >&2; die "не удалось собрать msitools, полный журнал: /tmp/msirb-build.log"; }
[ -x "$APP_DIR/msitools/bin/msibuild" ] || die "msibuild не найден после сборки"

# ---- лаунчер Aspia Host Portable (mingw-w64, собирается один раз)
log "Собираю лаунчер Aspia Host Portable"
"$SRC_DIR/scripts/build-portable-stub.sh" "$APP_DIR/portable" >/tmp/msirb-portable-build.log 2>&1 \
  || { tail -n 30 /tmp/msirb-portable-build.log >&2; die "не удалось собрать portable-стаб, полный журнал: /tmp/msirb-portable-build.log"; }
[ -f "$APP_DIR/portable/stub.exe" ] || die "stub.exe не найден после сборки"

# ---- конфигурация
set_kv() {  # set_kv KEY VALUE — обновить или добавить строку в env-файл
  local k="$1" v="$2" tmp
  tmp="$(mktemp)"
  grep -v "^${k}=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$k" "$v" >> "$tmp"
  cat "$tmp" > "$ENV_FILE"; rm -f "$tmp"
}
get_kv() { grep "^$1=" "$ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2- || true; }

FIRST_INSTALL=0
if [ ! -f "$ENV_FILE" ]; then
  FIRST_INSTALL=1
  : > "$ENV_FILE"
  set_kv MSIRB_HOST 0.0.0.0
  set_kv MSIRB_PORT 8080
  set_kv MSIRB_USER admin
  set_kv MSIRB_MAX_UPLOAD_MB 1024
  set_kv MSIRB_DATA_DIR "$DATA_DIR"
  set_kv MSIRB_SECRET "$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
fi
chown root:"$SVC_USER" "$ENV_FILE"; chmod 0640 "$ENV_FILE"

set_kv MSIRB_MSITOOLS_DIR "$APP_DIR/msitools"
set_kv MSIRB_PORTABLE_DIR "$APP_DIR/portable"
[ -z "$PORT" ]     || set_kv MSIRB_PORT "$PORT"
[ -z "$HOST" ]     || set_kv MSIRB_HOST "$HOST"
[ -z "$WEB_USER" ] || set_kv MSIRB_USER "$WEB_USER"

SHOW_PASSWORD=""
if [ "$NO_PASSWORD" -eq 1 ]; then
  set_kv MSIRB_PASSWORD ""
elif [ -n "$PASSWORD" ]; then
  set_kv MSIRB_PASSWORD "$PASSWORD"; SHOW_PASSWORD="$PASSWORD"
elif [ "$RESET_PASSWORD" -eq 1 ]; then
  SHOW_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(15))')"
  set_kv MSIRB_PASSWORD "$SHOW_PASSWORD"
fi
# по умолчанию (без флагов) MSIRB_PASSWORD не трогаем: при первой установке это открытый доступ,
# при повторной — сохраняется то, что уже было настроено

# ---- systemd
log "Настраиваю сервис systemd"
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Aspia Configurator (веб-сервис пересборки MSI-пакетов Aspia Host)
After=network.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$GUNICORN -c $APP_DIR/gunicorn.conf.py --chdir $APP_DIR server:app
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$APP_NAME.service" >/dev/null
systemctl restart "$APP_NAME.service"

# ---- проверка
CUR_PORT="$(get_kv MSIRB_PORT)"
log "Жду запуска сервиса на порту $CUR_PORT"
ok=0
for _ in $(seq 1 30); do
  if python3 - "$CUR_PORT" <<'PY' 2>/dev/null
import sys, urllib.request
sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:%s/healthz" % sys.argv[1], timeout=2).status == 200 else 1)
PY
  then ok=1; break; fi
  sleep 1
done
if [ "$ok" -ne 1 ]; then
  journalctl -u "$APP_NAME" -n 30 --no-pager || true
  die "сервис не запустился, см. журнал выше"
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "Готово. Aspia Configurator ($APP_NAME) запущен и включён в автозапуск."
echo "  Адрес:    http://${IP:-<адрес-сервера>}:$CUR_PORT/"
if [ -n "$SHOW_PASSWORD" ]; then
  echo "  Логин:    $(get_kv MSIRB_USER)"
  echo "  Пароль:   $SHOW_PASSWORD"
elif [ -n "$(get_kv MSIRB_PASSWORD)" ]; then
  echo "  Логин:    $(get_kv MSIRB_USER)"
  echo "  Пароль:   без изменений (хранится в $ENV_FILE)"
else
  echo "  Доступ:   БЕЗ ПАРОЛЯ — открыт всем, у кого есть сеть до порта $CUR_PORT"
  echo "            включить пароль: sudo ./install.sh --reset-password"
fi
echo "  Настройки: $ENV_FILE  (после правки: systemctl restart $APP_NAME)"
echo "  Журнал:   journalctl -u $APP_NAME -f"
if [ "$FIRST_INSTALL" -eq 1 ]; then
  echo "  Счётчик сборок: 0 (первая установка)"
else
  echo "  Счётчик сборок: $(cat "$DATA_DIR/build_count" 2>/dev/null || echo 0) (сохранён при обновлении)"
fi
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "  ufw активен — откройте порт: ufw allow $CUR_PORT/tcp"
fi
