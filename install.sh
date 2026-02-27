#!/usr/bin/env bash
set -euo pipefail

REPO_DEFAULT="https://github.com/zyy3096/sky-web.git"
DIR_DEFAULT="/opt/sky-web"
SERVICE_DEFAULT="sky-web"
BIND_HOST_DEFAULT="127.0.0.1"
PORT_DEFAULT="9876"

# 也可以用参数覆盖
REPO="${REPO_DEFAULT}"
DIR="${DIR_DEFAULT}"
SERVICE="${SERVICE_DEFAULT}"
BIND_HOST="${BIND_HOST_DEFAULT}"
PORT="${PORT_DEFAULT}"

# Web BasicAuth（强烈建议改）
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-CHANGE_ME_STRONG}"
FLASK_SECRET="${FLASK_SECRET:-CHANGE_ME_RANDOM_LONG}"

usage() {
  cat <<EOF
Usage: sudo bash install.sh [options]

Options:
  --repo <git_url>         (default: ${REPO_DEFAULT})
  --dir <path>             (default: ${DIR_DEFAULT})
  --service <name>         (default: ${SERVICE_DEFAULT})
  --bind <ip>              (default: ${BIND_HOST_DEFAULT})
  --port <port>            (default: ${PORT_DEFAULT})

Env:
  ADMIN_USER / ADMIN_PASSWORD / FLASK_SECRET
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --dir) DIR="$2"; shift 2;;
    --service) SERVICE="$2"; shift 2;;
    --bind) BIND_HOST="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

echo "[1/7] Install OS deps..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y git python3 python3-venv python3-pip
elif command -v yum >/dev/null 2>&1; then
  yum install -y git python3 python3-pip || true
else
  echo "Unsupported OS (need apt-get or yum)"
  exit 1
fi

echo "[2/7] Clone or update repo..."
if [[ -d "${DIR}/.git" ]]; then
  cd "${DIR}"
  git fetch --all
  git reset --hard origin/HEAD
else
  rm -rf "${DIR}"
  git clone "${REPO}" "${DIR}"
  cd "${DIR}"
fi

echo "[3/7] Validate repo files..."
if [[ ! -f app.py ]]; then
  echo "ERROR: app.py not found in repo"
  exit 2
fi
if [[ ! -f requirements.txt ]]; then
  echo "ERROR: requirements.txt not found in repo"
  exit 2
fi
if [[ ! -f templates/index.html ]]; then
  echo "ERROR: templates/index.html not found in repo"
  exit 2
fi

# 粗略检查：requirements.txt 不能是单行“带空格”的写法
if grep -qE '^[^#].* .*$' requirements.txt; then
  echo "ERROR: requirements.txt looks broken (one line with spaces)."
  echo "Fix it to one requirement per line, e.g.:"
  echo "  flask==3.0.3"
  echo "  requests==2.32.3"
  exit 2
fi

echo "[4/7] Create venv + install requirements..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[5/7] Python syntax check..."
python -m py_compile app.py || {
  echo "ERROR: app.py failed to compile. (Usually caused by lost newlines/indentation.)"
  exit 2
}

echo "[6/7] Create env file + systemd service..."
ENV_FILE="/etc/${SERVICE}.env"
cat >"${ENV_FILE}" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
FLASK_SECRET=${FLASK_SECRET}
BIND_HOST=${BIND_HOST}
PORT=${PORT}
EOF
chmod 600 "${ENV_FILE}"

cat >/etc/systemd/system/${SERVICE}.service <<EOF
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

systemctl daemon-reload
systemctl enable --now "${SERVICE}"

echo "[7/7] Done."
systemctl --no-pager --full status "${SERVICE}" || true
echo ""
echo "Access (recommended via SSH tunnel):"
echo "  ssh -L ${PORT}:${BIND_HOST}:${PORT} user@server"
echo "  then open: http://127.0.0.1:${PORT}"