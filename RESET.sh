#!/usr/bin/env bash
# padlocke-lab reset — deterministic: down, rebuild, fresh session key, health-gate.
# (The session key is generated on first boot inside the container; a fresh
#  container therefore also rotates the CBC seal key and wipes any vault drop
#  files a previous solve left behind.)
set -euo pipefail
cd "$(dirname "$0")"

docker compose down -v --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build >/dev/null

# gate on the service being actually alive (no blind sleeps)
for i in $(seq 1 40); do
  if curl -fsS -o /dev/null http://127.0.0.1:18962/api/health 2>/dev/null; then
    echo "RESET-OK padlocke http://127.0.0.1:18962"
    exit 0
  fi
  sleep 2
done
echo "RESET-DEGRADED service not answering after 80s — check: docker compose ps" >&2
exit 1
