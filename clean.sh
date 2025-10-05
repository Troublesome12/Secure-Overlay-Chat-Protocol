#!/usr/bin/env bash
set -euo pipefail

# ----------------------------------------------------------------------
# Clean local SOCP environment (servers, DB, keys, caches, downloads)
# ----------------------------------------------------------------------
# Usage:
#   ./clean.sh               -> cleans all except Master identity (and kills ports)
#   ./clean.sh --nuke-master -> also deletes Master UUID and PEM
# ----------------------------------------------------------------------

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Paths
DATA_DIR="$ROOT_DIR/data"
SQL_DB="$DATA_DIR/socp.db"
JSON_DB="$DATA_DIR/master_db.json"

KEYS_DIR="$ROOT_DIR/keys"
MASTER_UUID="$KEYS_DIR/master.uuid"
MASTER_PEM="$KEYS_DIR/master.pem"
SERVER_UUID="$KEYS_DIR/server.uuid"
SERVER_PEM="$KEYS_DIR/server.pem"

DOWNLOADS_DIR="$ROOT_DIR/downloads"
LOGS_DIR="$ROOT_DIR/logs"

NUKE_MASTER=0
[[ "${1:-}" == "--nuke-master" ]] && NUKE_MASTER=1

# Default ports to kill (override via env: PORTS="9101 9102")
PORTS=(${PORTS:-9101 9102 9103})

rm_if_exists() {
  local p="$1"
  if [[ -e "$p" || -L "$p" ]]; then
    echo "[-] rm $p"
    rm -rf -- "$p"
  fi
}

kill_ports() {
  echo "[*] Killing processes bound to SOCP ports: ${PORTS[*]}"
  for port in "${PORTS[@]}"; do
    echo "  → port :$port"
    if command -v lsof >/dev/null 2>&1; then
      PIDS=$(lsof -ti tcp:"$port" -sTCP:LISTEN || true)
      if [[ -n "${PIDS:-}" ]]; then
        echo "    kill $PIDS"
        kill $PIDS 2>/dev/null || true
        sleep 0.3
        kill -9 $PIDS 2>/dev/null || true
      else
        echo "    (no listener)"
      fi
    elif command -v fuser >/dev/null 2>&1; then
      fuser -k "${port}/tcp" || true
    else
      echo "    ⚠️  Neither 'lsof' nor 'fuser' found; cannot kill :$port"
    fi
  done
}

echo "[*] Cleaning SOCP workspace ..."

# --- 0) Kill ports by default ---
kill_ports

# --- 1) Runtime data ---
rm_if_exists "$SQL_DB"            # SQLite server store
rm_if_exists "$JSON_DB"           # Legacy JSON master DB
rm_if_exists "$DOWNLOADS_DIR"     # Received files
rm_if_exists "$LOGS_DIR"          # Logs (if any)

# --- 2) Local server identity ---
rm_if_exists "$SERVER_UUID"
rm_if_exists "$SERVER_PEM"

# --- 3) Dev & macOS caches ---
echo "[-] removing development caches"
rm -rf \
  "$ROOT_DIR/.pytest_cache" \
  "$ROOT_DIR/.mypy_cache" \
  "$ROOT_DIR/.ruff_cache" \
  "$ROOT_DIR/.DS_Store"

# --- 4) Python bytecode caches ---
if [[ -d "$ROOT_DIR/src" ]]; then
  find "$ROOT_DIR/src" -type d -name "__pycache__" -prune -exec rm -rf {} +
fi

# --- 5) Optional Master identity removal ---
if [[ $NUKE_MASTER -eq 1 ]]; then
  echo "[!] NUKING MASTER IDENTITY"
  rm_if_exists "$MASTER_UUID"
  rm_if_exists "$MASTER_PEM"
fi

# --- 6) Recreate directories ---
mkdir -p "$DATA_DIR" "$KEYS_DIR"

echo "[✓] Cleanup complete."
if [[ $NUKE_MASTER -eq 1 ]]; then
  echo "Note: Master identity removed. A new one will be generated on next start."
fi
