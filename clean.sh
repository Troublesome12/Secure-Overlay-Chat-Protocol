#!/usr/bin/env bash
set -euo pipefail

# ----------------------------------------------------------------------
# Clean local SOCP environment (servers, DB, keys, caches, downloads)
# ----------------------------------------------------------------------
# Usage:
#   ./clean.sh               -> cleans everything except Master identity (and kills ports)
#   ./clean.sh --nuke-master -> also deletes Master identity (master_server_*.pem)
# ----------------------------------------------------------------------

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Paths
DATA_DIR="$ROOT_DIR/data"
SQL_DB="$DATA_DIR/socp.db"
KEYS_DIR="$ROOT_DIR/keys"
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
rm_if_exists "$DOWNLOADS_DIR"     # Received files
rm_if_exists "$LOGS_DIR"          # Logs (if any)

# --- 2) Keys (handle real filenames like master_server_*.pem, server_*.pem, Alice.pem, Bob.pem) ---
if [[ -d "$KEYS_DIR" ]]; then
  shopt -s nullglob
  echo "[-] removing keys in $KEYS_DIR"
  for p in "$KEYS_DIR"/*.pem "$KEYS_DIR"/*.uuid; do
    base="$(basename "$p")"
    if [[ $NUKE_MASTER -eq 0 && "$base" == master_server_* ]]; then
      # keep master identity unless --nuke-master
      echo "    keep $base (master identity)"
      continue
    fi
    echo "    rm $base"
    rm -f -- "$p"
  done
  shopt -u nullglob
fi

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

# --- 5) Optional Master identity removal (redundant safety) ---
if [[ $NUKE_MASTER -eq 1 && -d "$KEYS_DIR" ]]; then
  echo "[!] NUKING MASTER IDENTITY (master_server_*.pem)"
  rm -f "$KEYS_DIR"/master_server_*.pem "$KEYS_DIR"/master*.uuid 2>/dev/null || true
fi

echo "[✓] Cleanup complete."
if [[ $NUKE_MASTER -eq 1 ]]; then
  echo "Note: Master identity removed. A new one will be generated on next start."
fi
