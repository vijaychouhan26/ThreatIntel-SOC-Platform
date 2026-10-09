#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$PROJECT_DIR/deploy/nginx/threatintel.conf"
TARGET="/etc/nginx/sites-available/threatintel"
WEB_ROOT="/var/www/threatintel"

if ! sudo test -f /etc/nginx/ssl/threatintel.crt || \
   ! sudo test -f /etc/nginx/ssl/threatintel.key; then
  echo "Install the TLS certificate and key under /etc/nginx/ssl first." >&2
  exit 1
fi

if [[ ! -f "$PROJECT_DIR/frontend/dist/index.html" ]]; then
  echo "Frontend production build is missing. Run: cd frontend && npm run build" >&2
  exit 1
fi

sudo install -d -o root -g www-data -m 0755 "$WEB_ROOT"
sudo cp -a "$PROJECT_DIR/frontend/dist/." "$WEB_ROOT/"
sudo chmod -R a=rX "$WEB_ROOT"

sed "s|@PROJECT_DIR@|$PROJECT_DIR|g" "$SOURCE" | sudo tee "$TARGET" >/dev/null
sudo ln -sfn "$TARGET" /etc/nginx/sites-enabled/threatintel
sudo nginx -t
if sudo systemctl is-active --quiet nginx; then
  sudo systemctl reload nginx
else
  sudo systemctl enable --now nginx
fi
echo "nginx TLS reverse proxy installed."
