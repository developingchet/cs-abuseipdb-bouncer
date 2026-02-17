#!/bin/sh
# bouncer-entrypoint.sh
#
# Renders the LAPI api_key from env into the config template, then execs
# the bouncer binary. The bouncer will spawn the reporter script and feed
# CrowdSec decisions to its stdin.

set -e

TMPL="/crowdsec-custom-bouncer.yaml.tmpl"
CONFIG="/tmp/bouncer-config.yaml"

_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
_log() { printf 'time="%s" level=%s msg="%s"\n' "$(_ts)" "$1" "$2" >&2; }

if [ -z "${CROWDSEC_ABUSEIPDB_BOUNCER_KEY:-}" ]; then
    _log error "CROWDSEC_ABUSEIPDB_BOUNCER_KEY not set"
    _log error "  run: docker exec crowdsec cscli bouncers add abuseipdb-reporter"
    _log error "  then add the printed key to .env as CROWDSEC_ABUSEIPDB_BOUNCER_KEY=<key>"
    exit 1
fi

if [ ! -f "$TMPL" ]; then
    _log error "config template not found: ${TMPL}"
    _log error "  ensure volume mount: ./config/crowdsec-custom-bouncer.yaml.tmpl:/crowdsec-custom-bouncer.yaml.tmpl:ro"
    exit 1
fi

sed "s@__CROWDSEC_ABUSEIPDB_BOUNCER_KEY__@${CROWDSEC_ABUSEIPDB_BOUNCER_KEY}@g" \
    "$TMPL" > "$CONFIG"

_log info "config rendered — starting bouncer"

exec /crowdsec-custom-bouncer -c "$CONFIG"
