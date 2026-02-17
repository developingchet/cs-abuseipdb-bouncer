#!/usr/bin/env ash
# crowdsec-abuseipdb-reporter.sh
#
# Reads CrowdSec decisions from stdin and reports eligible IPs to AbuseIPDB.
# Spawned by crowdsec-custom-bouncer with feed_via_stdin=true.
#
# Required env:
#   ABUSEIPDB_API_KEY
#
# Optional env:
#   ABUSEIPDB_DAILY_LIMIT      default: 1000  (free=1000, webmaster=3000, premium=50000)
#   ABUSEIPDB_PRECHECK         default: false (pre-check /check endpoint; separate 1000/day quota)
#   ABUSEIPDB_MIN_DURATION     default: 0     (skip decisions shorter than N seconds; 0=disabled)
#   LOG_LEVEL                  default: info  (info|debug)

set -eu

readonly REPORT_URL="https://api.abuseipdb.com/api/v2/report"
readonly CHECK_URL="https://api.abuseipdb.com/api/v2/check"
readonly COOLDOWN_SEC=900
readonly STATE_DIR="/tmp/cs-abuseipdb"
readonly COOLDOWN_DIR="${STATE_DIR}/cooldown"
readonly DAILY_FILE="${STATE_DIR}/daily"
readonly ORIGINS="crowdsec cscli"

# Write logs in logrus format to match crowdsec-custom-bouncer output.
# Targets /proc/1/fd/2 (the container's PID 1 stderr) because the bouncer
# does not inherit child process file descriptors into its own log stream.
# Falls back to plain stderr if /proc/1/fd/2 is not writable.
_log_fd=""
_init_log_fd() {
    if [ -w /proc/1/fd/2 ]; then
        _log_fd="/proc/1/fd/2"
    else
        _log_fd="/dev/stderr"
    fi
}

_log() {
    local level="$1"; shift
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    printf 'time="%s" level=%s msg="%s"\n' "$ts" "$level" "$*" >> "${_log_fd:-/dev/stderr}"
}

info()    { _log "info"    "$@"; }
warning() { _log "warning" "$@"; }
error()   { _log "error"   "$@"; }
debug() {
    case "${LOG_LEVEL:-info}" in
        debug|verbose) _log "debug" "$@" ;;
    esac
}

# --- cleanup -----------------------------------------------------------------

_cleanup() {
    find "$COOLDOWN_DIR" -maxdepth 1 -type f -mmin +15 -delete 2>/dev/null || true
    debug "exit: stale cooldown files pruned"
}
trap _cleanup EXIT INT TERM

# --- daily budget ------------------------------------------------------------

_today() { date -u '+%Y-%m-%d'; }

_read_daily() {
    local count fdate c d
    count=0
    fdate=$(_today)
    if [ -f "$DAILY_FILE" ]; then
        read -r c d < "$DAILY_FILE" || true
        [ "${d:-}" = "$fdate" ] && count="${c:-0}"
    fi
    printf '%s %s' "$count" "$fdate"
}

budget_ok() {
    local count line
    line=$(_read_daily)
    count="${line%% *}"
    [ "$count" -lt "${ABUSEIPDB_DAILY_LIMIT:-1000}" ]
}

bump_daily() {
    local count date line
    line=$(_read_daily)
    count="${line%% *}"
    date="${line#* }"
    count=$(( count + 1 ))
    printf '%s %s\n' "$count" "$date" > "$DAILY_FILE"
    printf '%s' "$count"
}

# --- per-IP cooldown ---------------------------------------------------------

_fname() { printf '%s' "${1%%/*}" | tr '.:/+' '____'; }

cooldown_ok() {
    local f elapsed last_ts now_ts
    f="${COOLDOWN_DIR}/$(_fname "$1")"
    [ -f "$f" ] || return 0
    last_ts=$(cat "$f")
    now_ts=$(date -u '+%s')
    elapsed=$(( now_ts - last_ts ))
    [ "$elapsed" -ge "$COOLDOWN_SEC" ]
}

mark_reported() { date -u '+%s' > "${COOLDOWN_DIR}/$(_fname "$1")"; }

_prune_counter=0
maybe_prune() {
    _prune_counter=$(( _prune_counter + 1 ))
    [ "$(( _prune_counter % 200 ))" -eq 0 ] || return 0
    find "$COOLDOWN_DIR" -maxdepth 1 -type f -mmin +15 -delete 2>/dev/null || true
    debug "maintenance: pruned stale cooldown files at decision=${_prune_counter}"
}

# --- address guards ----------------------------------------------------------

is_private() {
    local ip
    ip="${1%%/*}"
    printf '%s\n' "$ip" | grep -Eq \
        '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|0\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)' \
        && return 0
    printf '%s\n' "$ip" | grep -Eq \
        '^(::1$|[Ff][Ee]80:|[Ff][Cc][0-9A-Fa-f]|[Ff][Dd][0-9A-Fa-f])' \
        && return 0
    return 1
}

# --- duration parser ---------------------------------------------------------
# Converts Go duration strings (e.g. "143h58m15s", "3600s", "24h") to seconds.

duration_secs() {
    local d total num i c
    d="$1"
    total=0
    num=""
    i=0
    while [ "$i" -lt "${#d}" ]; do
        c=$(printf '%s' "$d" | cut -c$(( i + 1 )))
        case "$c" in
            [0-9]) num="${num}${c}" ;;
            h) total=$(( total + ${num:-0} * 3600 )); num="" ;;
            m) total=$(( total + ${num:-0} * 60  )); num="" ;;
            s) total=$(( total + ${num:-0}        )); num="" ;;
        esac
        i=$(( i + 1 ))
    done
    printf '%s' "$total"
}

# --- pre-check ---------------------------------------------------------------
# Calls /check before reporting to skip whitelisted IPs.
# Only active when ABUSEIPDB_PRECHECK=true.
# Check and report quotas are independent: both 1000/day on the free tier.
# Returns 1 (skip) if the IP is whitelisted; 0 otherwise.

precheck() {
    local ip tmp http_code wl
    [ "${ABUSEIPDB_PRECHECK:-false}" = "true" ] || return 0

    ip="${1%%/*}"
    tmp=$(mktemp)

    # Assign separately — local masks exit codes under set -e
    http_code=$(curl -s --tlsv1.2 --max-time 10 \
        -G "$CHECK_URL" \
        --data-urlencode "ipAddress=${ip}" \
        -d "maxAgeInDays=1" \
        -H "Key: ${ABUSEIPDB_API_KEY}" \
        -H "Accept: application/json" \
        -o "$tmp" -w '%{http_code}') || { rm -f "$tmp"; return 0; }

    wl=$(jq -r '.data.isWhitelisted // false' < "$tmp" 2>/dev/null)
    rm -f "$tmp"

    if [ "$wl" = "true" ]; then
        info "skip whitelisted ip=${ip}"
        return 1
    fi
    return 0
}

# --- scenario → category mapping ---------------------------------------------
#
# Strips the author prefix before matching ("crowdsecurity/ssh-bf" → "ssh-bf").
# First match wins; ordered specific before broad.
#
#  1  DNS Compromise    9  Open Proxy       17 Spoofing
#  2  DNS Poisoning    10  Web Spam         18 Brute-Force
#  3  Fraud Orders     11  Email Spam       19 Bad Web Bot
#  4  DDoS Attack      12  Blog Spam        20 Exploited Host
#  5  FTP Brute-Force  13  VPN IP           21 Web App Attack
#  6  Ping of Death    14  Port Scan        22 SSH
#  7  Phishing         15  Hacking          23 IoT Targeted
#  8  Fraud VoIP       16  SQL Injection

categories() {
    local s
    s=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    s="${s##*/}"
    case "$s" in
        *ssh*)                                          printf '22,18' ;;
        *ftp*)                                          printf '5,18'  ;;
        *sqli*|*sql-inj*|*sql_inj*)                    printf '16,21' ;;
        *xss*)                                          printf '21'    ;;
        *wordpress*|*wp-login*|*wp_login*|\
        *drupal*|*joomla*|*magento*|*prestashop*)       printf '18,21' ;;
        *http-dos*|*http-flood*|*ddos*|*flood*|*-dos*)  printf '4'     ;;
        *open-proxy*|*open_proxy*|*proxy*|*tor*)        printf '9'     ;;
        *crawl*|*bad-user-agent*|*bad_user_agent*|\
        *robot*|*scraper*|*spider*|*w00tw00t*)          printf '19'    ;;
        *probing*|*scan*|*enum*)                        printf '14,21' ;;
        *appsec*|*vpatch*)                              printf '21'    ;;
        *backdoor*|*rce*|*exploit*|*lfi*|*rfi*|\
        *traversal*|*path-trav*|*log4*|*spring4*|\
        *sensitive*)                                    printf '21,20' ;;
        *cve*)                                          printf '21,20' ;;
        *iot*|*mirai*|*telnet*)                         printf '23,20' ;;
        *smtp*|*email-spam*|*email_spam*|*imap*|*pop3*) printf '11,18' ;;
        *http-spam*|*web-spam*|*comment-spam*|\
        *blog-spam*|*comment_spam*)                     printf '10,12' ;;
        *phish*)                                        printf '7'     ;;
        *spoof*)                                        printf '17'    ;;
        *vpn*)                                          printf '13'    ;;
        *dns*)                                          printf '1'     ;;
        *ping*|*icmp*)                                  printf '6'     ;;
        *voip*)                                         printf '8'     ;;
        *fraud*|*card*)                                 printf '3'     ;;
        *authelia*)                                     printf '18'    ;;
        *iptables*|*port*|*nmap*|*masscan*|*zmap*)      printf '14'    ;;
        *brute*|*-bf*|*_bf*|*rdp*|*sip*|*vnc*)         printf '18'    ;;
        *http*|*web*|*nginx*|*apache*|*iis*)            printf '21'    ;;
        *)                                              printf '15'    ;;
    esac
}

# --- AbuseIPDB report with exponential backoff retry ------------------------

_do_report() {
    local ip cats comment tmp http_code body wait detail

    # Declare all locals at the top — avoids masking exit codes under set -e
    # and prevents accidental variable leakage from outer scopes.
    ip="${1%%/*}"
    cats="$2"
    comment="$3"
    tmp=$(mktemp)
    http_code=""
    body=""
    wait=""
    detail=""

    http_code=$(curl -s --tlsv1.2 --max-time 15 \
        -X POST "$REPORT_URL" \
        -H "Key: ${ABUSEIPDB_API_KEY}" \
        -H "Accept: application/json" \
        --data-urlencode "ip=${ip}" \
        --data-urlencode "categories=${cats}" \
        --data-urlencode "comment=${comment}" \
        -o "$tmp" -w '%{http_code}') || {
        rm -f "$tmp"
        error "curl network error ip=${ip}"
        return 1
    }

    body=$(cat "$tmp")
    rm -f "$tmp"

    case "$http_code" in
        200)
            return 0
            ;;
        422)
            detail=$(printf '%s' "$body" \
                | jq -r '.errors[0].detail // "no detail"' 2>/dev/null || printf 'parse error')
            debug "skip duplicate/invalid ip=${ip} detail=${detail}"
            return 1
            ;;
        429)
            wait=$(printf '%s' "$body" \
                | jq -r '.errors[0].detail // ""' 2>/dev/null \
                | grep -oE '[0-9]+' | head -1)
            warning "rate-limited sleep=${wait:-60}s — check daily quota at abuseipdb.com/account"
            sleep "${wait:-60}"
            return 1
            ;;
        401)
            error "401 unauthorized — verify ABUSEIPDB_API_KEY in .env"
            return 2
            ;;
        000)
            error "network error connecting to AbuseIPDB ip=${ip}"
            return 1
            ;;
        *)
            warning "unexpected http=${http_code} ip=${ip}"
            debug "response body: $(printf '%s' "$body" | head -c 200)"
            return 1
            ;;
    esac
}

report() {
    local attempt wait rc
    attempt=1
    wait=5
    rc=0

    while [ "$attempt" -le 3 ]; do
        _do_report "$@" || rc=$?
        [ "$rc" -eq 0 ] && return 0
        [ "$rc" -eq 2 ] && return 1
        if [ "$attempt" -lt 3 ]; then
            warning "retry attempt=${attempt}/3 wait=${wait}s ip=${1%%/*}"
            sleep "$wait"
            wait=$(( wait * 2 ))
        fi
        attempt=$(( attempt + 1 ))
    done
    return 1
}

# --- startup validation ------------------------------------------------------

validate() {
    local err used line

    _init_log_fd
    err=0

    if [ -z "${ABUSEIPDB_API_KEY:-}" ]; then
        error "ABUSEIPDB_API_KEY not set — add to .env: ABUSEIPDB_API_KEY=<key>"
        error "  get your key at: https://www.abuseipdb.com/account/api"
        err=$(( err + 1 ))
    fi

    command -v jq   >/dev/null 2>&1 || {
        error "jq not found — should be present in the Docker image (Dockerfile.bouncer)"
        err=$(( err + 1 ))
    }

    command -v curl >/dev/null 2>&1 || {
        error "curl not found — should be present in the Docker image (Dockerfile.bouncer)"
        err=$(( err + 1 ))
    }

    [ "$err" -gt 0 ] && {
        error "fatal: ${err} startup error(s) — exiting"
        exit 1
    }

    # Defaults
    : "${ABUSEIPDB_DAILY_LIMIT:=1000}"
    : "${ABUSEIPDB_PRECHECK:=false}"
    : "${ABUSEIPDB_MIN_DURATION:=0}"

    # Strip any whitespace from LOG_LEVEL (protects against .env CRLF or trailing spaces)
    LOG_LEVEL=$(printf '%s' "${LOG_LEVEL:-info}" | tr -d '[:space:]')

    # Verify the state directory is writable — catches volume mount issues early
    if ! mkdir -p "$COOLDOWN_DIR" 2>/dev/null || ! touch "${STATE_DIR}/.write_test" 2>/dev/null; then
        error "state directory not writable: ${STATE_DIR}"
        error "  ensure the volume is mounted: - /docker/crowdsec/abuseipdb-state:/tmp/cs-abuseipdb"
        exit 1
    fi
    rm -f "${STATE_DIR}/.write_test"

    line=$(_read_daily)
    used="${line%% *}"

    info "reporter started limit=${ABUSEIPDB_DAILY_LIMIT} used_today=${used} cooldown=${COOLDOWN_SEC}s precheck=${ABUSEIPDB_PRECHECK} min_duration=${ABUSEIPDB_MIN_DURATION}s log_level=${LOG_LEVEL}"
}

# --- main --------------------------------------------------------------------

main() {
    validate

    local line action origin scenario scope value duration dec_id
    local parsed cats comment count dur allowed o scope_lc

    line=""
    action=""
    origin=""
    scenario=""
    scope=""
    value=""
    duration=""
    dec_id=""
    parsed=""
    cats=""
    comment=""
    count=0
    dur=0
    allowed=0
    o=""
    scope_lc=""

    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$(printf '%s' "$line" | tr -d '[:space:]')" ] && continue

        maybe_prune

        # All fields extracted in a single jq call.
        # local + assignment are always on separate lines to avoid masking
        # non-zero exit codes under set -e.
        parsed=$(printf '%s' "$line" | jq -r '
            (.action   // ""),
            (.origin   // ""),
            (.scenario // "unknown"),
            (.scope    // ""),
            (.value    // ""),
            (.duration // "0s"),
            (.id       // 0 | tostring)
        ' 2>/dev/null) || {
            warning "json parse error: $(printf '%s' "$line" | head -c 100)"
            continue
        }

        action=$(   printf '%s' "$parsed" | sed -n '1p')
        origin=$(   printf '%s' "$parsed" | sed -n '2p')
        scenario=$( printf '%s' "$parsed" | sed -n '3p')
        scope=$(    printf '%s' "$parsed" | sed -n '4p')
        value=$(    printf '%s' "$parsed" | sed -n '5p')
        duration=$( printf '%s' "$parsed" | sed -n '6p')
        dec_id=$(   printf '%s' "$parsed" | sed -n '7p')

        debug "decision id=${dec_id} action=${action} origin=${origin} scope=${scope} value=${value} scenario=${scenario}"

        # Only new bans — del = expiry, not a new offence
        [ "$action" = "add" ] || continue

        # Impossible-travel decisions are account heuristics, not IP abuse
        case "$scenario" in
            *impossible-travel*|*impossible_travel*) continue ;;
        esac

        # Only locally-detected decisions — excludes CAPI/community blocklist
        allowed=0
        for o in $ORIGINS; do
            [ "$origin" = "$o" ] && allowed=1 && break
        done
        [ "$allowed" -eq 1 ] || { debug "skip origin=${origin} ip=${value}"; continue; }

        # AbuseIPDB accepts single IPs only
        scope_lc=$(printf '%s' "$scope" | tr '[:upper:]' '[:lower:]')
        [ "$scope_lc" = "ip" ] || { debug "skip scope=${scope} ip=${value}"; continue; }

        [ -n "$value" ] || continue

        is_private "$value" && { debug "skip private ip=${value}"; continue; }

        if [ "${ABUSEIPDB_MIN_DURATION:-0}" -gt 0 ]; then
            dur=$(duration_secs "$duration")
            [ "$dur" -lt "$ABUSEIPDB_MIN_DURATION" ] && {
                debug "skip short duration=${duration} secs=${dur} ip=${value}"
                continue
            }
        fi

        budget_ok || {
            warning "daily cap reached limit=${ABUSEIPDB_DAILY_LIMIT} dropping ip=${value}"
            warning "  cap resets at UTC midnight — see ABUSEIPDB_DAILY_LIMIT in .env"
            continue
        }

        cooldown_ok "$value" || { debug "skip cooldown ip=${value}"; continue; }

        precheck "$value" || continue

        cats=$(categories "$scenario")
        comment="CrowdSec detection | scenario: ${scenario##*/}"

        info "reporting ip=${value} id=${dec_id} scenario=${scenario##*/} cats=${cats}"

        if report "$value" "$cats" "$comment"; then
            mark_reported "$value"
            count=$(bump_daily)
            info "reported ip=${value} daily=${count}/${ABUSEIPDB_DAILY_LIMIT}"
        else
            debug "skipped ip=${value} id=${dec_id}"
        fi
    done

    info "stdin closed"
}

main "$@"
