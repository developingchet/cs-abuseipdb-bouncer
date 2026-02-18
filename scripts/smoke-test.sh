#!/usr/bin/env bash
# smoke-test.sh — Live-fire validation for cs-abuseipdb-bouncer v2.0
# Usage: bash scripts/smoke-test.sh
# Requires: docker, curl, go, jq

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Tracking ──────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
STEP=0

pass() { ((PASS++)); echo -e "${GREEN}[PASS]${RESET} $*"; }
fail() { ((FAIL++)); echo -e "${RED}[FAIL]${RESET} $*"; }
info() { echo -e "${CYAN}[INFO]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }

step() {
  ((STEP++))
  printf '\n'
  echo -e "${BOLD}── STEP %-2s %s${RESET}" "${STEP}" "$*"
}

# ── Constants ─────────────────────────────────────────────────────────────────
METRICS_URL="http://localhost:9090/metrics"
HEALTHZ_URL="http://localhost:9090/healthz"
READYZ_URL="http://localhost:9090/readyz"
TEST_IP="203.0.113.42"          # RFC 5737 TEST-NET-3 — never a real report target
VOLUME_NAME="bouncer-state"
HEALTHZ_TIMEOUT=30              # seconds to wait for /healthz

# ── Step 1: Prerequisites ─────────────────────────────────────────────────────
step "Prerequisites check"

for cmd in docker curl go jq; do
  if command -v "$cmd" &>/dev/null; then
    pass "$cmd found ($(command -v "$cmd"))"
  else
    fail "$cmd not found — install it and retry"
  fi
done

if [[ $FAIL -gt 0 ]]; then
  echo -e "\n${RED}Prerequisites not met. Aborting.${RESET}"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  warn "Not running as root. Accessing Docker volume mountpoints may require sudo."
  warn "If STEP 8 fails with permission denied, re-run: sudo bash scripts/smoke-test.sh"
fi

# ── Step 2: Start stack ────────────────────────────────────────────────────────
step "Start stack — docker compose up -d"

if docker compose up -d 2>&1; then
  pass "docker compose up -d succeeded"
else
  fail "docker compose up -d failed"
  echo -e "\n${RED}Stack failed to start. Aborting.${RESET}"
  exit 1
fi

# ── Step 3: Wait for /healthz ──────────────────────────────────────────────────
step "Wait for /healthz (timeout ${HEALTHZ_TIMEOUT}s)"

ELAPSED=0
HEALTHY=false
while [[ $ELAPSED -lt $HEALTHZ_TIMEOUT ]]; do
  if curl -sf "$HEALTHZ_URL" -o /dev/null 2>/dev/null; then
    HEALTHY=true
    break
  fi
  sleep 2
  ((ELAPSED+=2))
  info "Waiting... ${ELAPSED}s elapsed"
done

if $HEALTHY; then
  pass "/healthz responded within ${ELAPSED}s"
else
  fail "/healthz did not respond within ${HEALTHZ_TIMEOUT}s"
  docker compose logs --tail=30
  exit 1
fi

# ── Step 4: /metrics assertions ────────────────────────────────────────────────
step "/metrics assertions — check for 5 cs_abuseipdb_* metric names"

METRICS_BODY=$(curl -sf "$METRICS_URL" 2>/dev/null || true)

REQUIRED_METRICS=(
  "cs_abuseipdb_decisions_processed_total"
  "cs_abuseipdb_reports_sent_total"
  "cs_abuseipdb_decisions_skipped_total"
  "cs_abuseipdb_api_errors_total"
  "cs_abuseipdb_quota_remaining"
)

for metric in "${REQUIRED_METRICS[@]}"; do
  if echo "$METRICS_BODY" | grep -q "$metric"; then
    pass "metric present: $metric"
  else
    fail "metric missing: $metric"
  fi
done

# ── Step 5: /healthz assertion ─────────────────────────────────────────────────
step "/healthz assertion — body='ok', HTTP 200"

HTTP_CODE=$(curl -s -o /tmp/smoke_healthz_body -w "%{http_code}" "$HEALTHZ_URL")
BODY=$(cat /tmp/smoke_healthz_body)

if [[ "$HTTP_CODE" == "200" ]]; then
  pass "/healthz HTTP $HTTP_CODE"
else
  fail "/healthz HTTP $HTTP_CODE (expected 200)"
fi

if [[ "$BODY" == "ok" ]]; then
  pass "/healthz body = 'ok'"
else
  fail "/healthz body = '$BODY' (expected 'ok')"
fi

# ── Step 6: /readyz assertion ──────────────────────────────────────────────────
step "/readyz assertion — HTTP 200 or 503 both valid (no real LAPI)"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$READYZ_URL")
if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "503" ]]; then
  pass "/readyz HTTP $HTTP_CODE (acceptable without real LAPI)"
else
  fail "/readyz HTTP $HTTP_CODE (expected 200 or 503)"
fi

# ── Step 7: Stop container to release bbolt file lock ─────────────────────────
step "Stop container — docker compose stop (releases bbolt lock)"

if docker compose stop 2>&1; then
  pass "docker compose stop succeeded"
else
  fail "docker compose stop failed"
  exit 1
fi

# ── Step 8: Inject state via inject_state tool ────────────────────────────────
step "Inject state — go run scripts/inject_state/main.go"

# Locate the volume mountpoint on the host
MOUNTPOINT=$(docker volume inspect "$VOLUME_NAME" --format '{{.Mountpoint}}' 2>/dev/null || true)

if [[ -z "$MOUNTPOINT" ]]; then
  fail "Could not find volume '$VOLUME_NAME' mountpoint. Is the volume created?"
  FAIL=$((FAIL+1))
else
  info "Volume mountpoint: $MOUNTPOINT"
  DB_PATH="${MOUNTPOINT}/state.db"

  if go run scripts/inject_state/main.go \
      --db "$DB_PATH" \
      --cooldown-ip "$TEST_IP" 2>&1; then
    pass "State injection succeeded"
  else
    fail "State injection failed (check permissions — try sudo)"
  fi
fi

# ── Step 9: Restart container ─────────────────────────────────────────────────
step "Restart container — docker compose start"

if docker compose start 2>&1; then
  pass "docker compose start succeeded"
else
  fail "docker compose start failed"
  exit 1
fi

# Wait for /healthz again after restart
info "Waiting for /healthz after start..."
ELAPSED=0
HEALTHY=false
while [[ $ELAPSED -lt $HEALTHZ_TIMEOUT ]]; do
  if curl -sf "$HEALTHZ_URL" -o /dev/null 2>/dev/null; then
    HEALTHY=true
    break
  fi
  sleep 2
  ((ELAPSED+=2))
done

if $HEALTHY; then
  pass "/healthz responsive after start (${ELAPSED}s)"
else
  fail "/healthz did not respond within ${HEALTHZ_TIMEOUT}s after start"
  exit 1
fi

# ── Step 10: Quota gauge check ─────────────────────────────────────────────────
step "Quota gauge check — cs_abuseipdb_quota_remaining ≤ (limit - 42)"

METRICS_BODY=$(curl -sf "$METRICS_URL" 2>/dev/null || true)
QUOTA_LINE=$(echo "$METRICS_BODY" | grep '^cs_abuseipdb_quota_remaining ' || true)

if [[ -z "$QUOTA_LINE" ]]; then
  fail "cs_abuseipdb_quota_remaining not found in /metrics"
else
  QUOTA_VALUE=$(echo "$QUOTA_LINE" | awk '{print $2}' | cut -d'.' -f1)
  info "cs_abuseipdb_quota_remaining = $QUOTA_VALUE"

  # Injected count=42 so remaining should be at most (limit - 42)
  # We can't know the exact limit without env, but we verify it's ≤ 958 (1000-42)
  if [[ "$QUOTA_VALUE" -le 958 ]]; then
    pass "quota_remaining=$QUOTA_VALUE ≤ 958 (limit-42 at default 1000) — state loaded"
  else
    fail "quota_remaining=$QUOTA_VALUE > 958 — injected state may not have loaded"
  fi
fi

# ── Step 11: Persistence test ──────────────────────────────────────────────────
step "Persistence test — docker compose restart; check quota again"

if docker compose restart 2>&1; then
  pass "docker compose restart succeeded"
else
  fail "docker compose restart failed"
  exit 1
fi

info "Waiting for /healthz after restart..."
ELAPSED=0
HEALTHY=false
while [[ $ELAPSED -lt $HEALTHZ_TIMEOUT ]]; do
  if curl -sf "$HEALTHZ_URL" -o /dev/null 2>/dev/null; then
    HEALTHY=true
    break
  fi
  sleep 2
  ((ELAPSED+=2))
done

if ! $HEALTHY; then
  fail "/healthz did not respond within ${HEALTHZ_TIMEOUT}s after restart"
  exit 1
fi

METRICS_BODY=$(curl -sf "$METRICS_URL" 2>/dev/null || true)
QUOTA_LINE=$(echo "$METRICS_BODY" | grep '^cs_abuseipdb_quota_remaining ' || true)

if [[ -z "$QUOTA_LINE" ]]; then
  fail "cs_abuseipdb_quota_remaining not found after restart"
else
  QUOTA_VALUE=$(echo "$QUOTA_LINE" | awk '{print $2}' | cut -d'.' -f1)
  info "cs_abuseipdb_quota_remaining after restart = $QUOTA_VALUE"

  if [[ "$QUOTA_VALUE" -le 958 ]]; then
    pass "quota_remaining=$QUOTA_VALUE persisted across restart"
  else
    fail "quota_remaining=$QUOTA_VALUE — state did not persist across restart"
  fi
fi

# ── Step 12: Final Report ──────────────────────────────────────────────────────
printf '\n'
echo "══════════════════════════════════════════════"
echo -e "${BOLD}  Smoke Test Report${RESET}"
echo "══════════════════════════════════════════════"
echo -e "  ${GREEN}PASS${RESET}: $PASS"
echo -e "  ${RED}FAIL${RESET}: $FAIL"
echo "══════════════════════════════════════════════"

if [[ $FAIL -gt 0 ]]; then
  echo -e "${RED}Result: FAILED ($FAIL failure(s))${RESET}"
  exit 1
else
  echo -e "${GREEN}Result: ALL PASSED${RESET}"
  exit 0
fi
