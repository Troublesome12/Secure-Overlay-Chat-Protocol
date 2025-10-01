#!/usr/bin/env bash
# clean.sh — minimal reset for SOCP dev
# Usage:
#    chmod +x clean.sh    # add permission
#    ./clean.sh           # clean state, keep master identity
#    ./clean.sh --nuke-master   # ALSO wipe master identity

set -euo pipefail

NUKE="${1:-}"

# Stop any running servers/clients (best effort)
pkill -f "src/main.py server" 2>/dev/null || true
pkill -f "src/main.py client" 2>/dev/null || true

# Making ports avaiable
for p in 9101 9102; do
  pids="$(lsof -ti tcp:$p 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    echo "Freeing port $p (pids: $pids)"
    kill $pids 2>/dev/null || true
    sleep 0.5
    # force if still listening
    pids2="$(lsof -ti tcp:$p 2>/dev/null || true)"
    [ -n "$pids2" ] && kill -9 $pids2 2>/dev/null || true
  fi
done

# Remove Python bytecode
find src -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find src -name '*.pyc' -delete 2>/dev/null || true

# Reset runtime data (keep master identity)
rm -f data/master_db.json
rm -f keys/server.uuid
rm -f keys/server_*.pem 2>/dev/null || true
rm -f keys/Alice.pem keys/Bob.pem 2>/dev/null || true
rm -rf downloads   

# Optional: nuke master identity too
if [[ "$NUKE" == "--nuke-master" ]]; then
  if [[ -f keys/master.uuid ]]; then
    MASTER_UUID="$(cat keys/master.uuid || true)"
    [[ -n "$MASTER_UUID" ]] && rm -f "keys/${MASTER_UUID}.pem"
  fi
  rm -f keys/master.uuid
fi

echo "Clean complete."
