#!/usr/bin/env bash
# Удаление Aspia Configurator. По умолчанию данные (пакеты, настройки) остаются; --purge удаляет всё.
set -eu

APP_NAME=msi-rebuilder
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "Запустите от root: sudo ./uninstall.sh [--purge]" >&2; exit 1; }

systemctl disable --now "$APP_NAME.service" 2>/dev/null || true
rm -f "/etc/systemd/system/$APP_NAME.service"
systemctl daemon-reload
rm -rf "/opt/$APP_NAME"

if [ "$PURGE" -eq 1 ]; then
  rm -rf "/var/lib/$APP_NAME" "/etc/$APP_NAME"
  id msirb >/dev/null 2>&1 && userdel msirb || true
  echo "Сервис удалён вместе с данными и настройками."
else
  echo "Сервис удалён. Данные (/var/lib/$APP_NAME) и настройки (/etc/$APP_NAME) сохранены; --purge удалит и их."
fi
echo "Пакеты msitools, gcab, python3-flask, gunicorn остались в системе."
