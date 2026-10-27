#!/bin/bash
# Re-runs the original attack steps against the MITIGATED stack and
# confirms each one now fails. Run after: docker compose up -d
#
# Target: http://localhost:8080  (mitigated nginx, see docker-compose.yml)

BASE="http://localhost:8080"

echo "=== [1] Cache Poisoning attempt (X-Forwarded-Host) ==="
docker compose exec nginx sh -c 'rm -rf /var/cache/nginx/*' 2>/dev/null

curl -s -H "X-Forwarded-Host: attacker.evil.com" "$BASE/" | grep -i "attacker.evil.com" \
  && echo "[FAIL] attacker host leaked into response" \
  || echo "[PASS] attacker host NOT reflected in response"

echo
echo "=== [2] Web Cache Deception attempt (/account/*.css) ==="
curl -s -o /dev/null -w "HTTP status: %{http_code}\n" "$BASE/account/x.css"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/account/x.css")
if [ "$STATUS" = "404" ]; then
  echo "[PASS] /account/x.css returns 404 (no sensitive data exposed)"
else
  echo "[FAIL] /account/x.css returned $STATUS"
fi

CACHE_STATUS=$(curl -s -i "$BASE/account/x.css" | grep -i "X-Cache-Status" || true)
if [ -z "$CACHE_STATUS" ]; then
  echo "[PASS] no X-Cache-Status header (not cached)"
else
  echo "[CHECK] $CACHE_STATUS"
fi

echo
echo "=== [3] Static page JS injection attempt ==="
curl -s -H "X-Forwarded-Host: attacker.evil.com" "$BASE/static-page" | grep -i "attacker.evil.com" \
  && echo "[FAIL] attacker host leaked into script src" \
  || echo "[PASS] script src NOT pointing to attacker host"
