#!/usr/bin/env bash
set -euo pipefail

REPO="${REPO:-https://github.com/zyy3096/sky-web.git}"
DIR="${DIR:-/opt/sky-web}"
SERVICE="${SERVICE:-sky-web}"
PORT_DEFAULT="${PORT_DEFAULT:-9876}"

echo "[1/7] Install OS deps..."
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y git python3 python3-venv python3-pip
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y git python3 python3-pip || true
else
  echo "Unsupported OS (need apt-get or yum)"
  exit 1
fi

echo "[2/7] Clone repo..."
sudo rm -rf "$DIR"
sudo git clone "$REPO" "$DIR"
sudo chown -R "$USER":"$USER" "$DIR"
cd "$DIR"

echo "[3/7] Create venv + install requirements..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[4/7] Prompt for web auth + bind..."
read -rp "Web bind host (127.0.0.1=本机/SSH隧道, 0.0.0.0=局域网直接访问) [127.0.0.1]: " BIND_HOST
BIND_HOST="${BIND_HOST:-127.0.0.1}"

read -rp "Web port [${PORT_DEFAULT}]: " PORT
PORT="${PORT:-${PORT_DEFAULT}}"

read -rp "ADMIN_USER (BasicAuth) [admin]: " ADMIN_USER
ADMIN_USER="${ADMIN_USER:-admin}"

while true; do
  read -rsp "ADMIN_PASSWORD (BasicAuth, 必填): " ADMIN_PASSWORD
  echo
  if [[ -n "${ADMIN_PASSWORD}" ]]; then
    break
  fi
done

FLASK_SECRET="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"

echo "[5/7] Validate python..."
python -m py_compile app.py

echo "[6/7] Write env + systemd service..."
ENV_FILE="/etc/${SERVICE}.env"
sudo bash -c "cat > '${ENV_FILE}'" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
FLASK_SECRET=${FLASK_SECRET}
BIND_HOST=${BIND_HOST}
PORT=${PORT}
EOF
sudo chmod 600 "${ENV_FILE}"

sudo bash -c "cat > '/etc/systemd/system/${SERVICE}.service'" <<EOF
[Unit]
Description=sky-web qb controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${DIR}/venv/bin/python ${DIR}/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now "${SERVICE}"

echo "[7/7] Done."
sudo systemctl --no-pager --full status "${SERVICE}" || true
echo ""
echo "Access:"
if [[ "${BIND_HOST}" == "127.0.0.1" ]]; then
  echo "  推荐 SSH 隧道：ssh -L ${PORT}:127.0.0.1:${PORT} <user>@<server_ip>"
  echo "  然后打开：http://127.0.0.1:${PORT}"
else
  echo "  直接打开：http://<server_ip>:${PORT}"
fi
