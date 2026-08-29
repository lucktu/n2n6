#!/bin/sh
# renewsn.sh: Renew n2n supernode via DNS failover (shell version)
# For embedded systems without Python (Padavan, OpenWRT, etc.)
#
# Requirements:
#   - wget (busybox wget works, needed for DNSPod API calls)
#   - nc OR netcat (only needed for the UDP n2n business-layer probe;
#     probing falls back to tcp-only with a warning if neither is present)
#   - wc (busybox standard; counts the UDP reply bytes)
#   - logger (optional, for syslog)
#
# Usage:
#   1. Copy renewsn.conf to /etc/renewsn.conf and edit it
#   2. Run: /path/to/renewsn.sh &
#   3. Add to startup: echo '/path/to/renewsn.sh &' >> /etc/firewall.user

# ============================================================
# Config
# ============================================================

CONFIG_FILE="/etc/renewsn.conf"

# ============================================================
# Load config
# ============================================================

# Default values
INTERVAL=30
PROBE_TIMEOUT=3
CANDIDATES=""
DNS_TOKEN=""
DNS_DOMAIN=""
DNS_SUB_DOMAIN=""
DNS_TTL=600
LOG_ENABLED=1
# Probe method. Default is "udp": n2n supernodes are UDP services, so the
# REGISTER_SUPER business-layer check is what truly tells good from bad.
#   udp  = UDP REGISTER_SUPER reply (default, most accurate for n2n SN)
#   tcp  = TCP port alive only (useful when the SN sits behind a TCP tunnel)
#   both = both checks must pass (most strict)
PROBE_METHOD="udp"
# n2n community name for the UDP REGISTER_SUPER business-layer probe.
# MUST match the community your edge actually uses; a mismatched community
# gets no reply and the SN is judged dead.
COMMUNITY="n2n"
# Set to 1 to log how many UDP reply bytes each failed probe got (debugging)
UDP_DIAG=0
# Consecutive probe failures before a candidate is considered unusable.
# A single transient miss (network blip, DNS hiccup) does NOT trigger a switch;
# the SN must fail this many consecutive rounds before the next one takes over.
FAIL_THRESHOLD=3

if [ -f "$CONFIG_FILE" ]; then
    . "$CONFIG_FILE"
else
    # Try current directory
    SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "$SELF_DIR/renewsn.conf" ]; then
        . "$SELF_DIR/renewsn.conf"
    fi
fi

# ============================================================
# Logging
# ============================================================

log_info() {
    if [ "$LOG_ENABLED" = "1" ]; then
        logger -t renewsn "$1" 2>/dev/null
    fi
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >&2
}

log_warn() {
    if [ "$LOG_ENABLED" = "1" ]; then
        logger -t renewsn "WARNING: $1" 2>/dev/null
    fi
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1" >&2
}

log_error() {
    if [ "$LOG_ENABLED" = "1" ]; then
        logger -t renewsn "ERROR: $1" 2>/dev/null
    fi
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >&2
}

# ============================================================
# SN probing
# ============================================================

# Probe SN via TCP using wget
# Uses wget -s (spider) to check if TCP port is open.
# If port is open (even for non-HTTP), wget connects and returns a non-refused error.
# If port is closed, wget returns "Connection refused".
# Returns 0 if alive, 1 if dead
probe_sn_tcp() {
    host="$1"
    port="$2"
    timeout="$3"
    
    err=$(wget -q -s -T "$timeout" -t 1 -O /dev/null "http://$host:$port/" 2>&1)
    case "$err" in
        *"Connection refused"*) return 1 ;;
        *"Connection timed out"*) return 1 ;;
        *"No route to host"*) return 1 ;;
        *"Name or service not known"*) return 1 ;;
        *"Network is unreachable"*) return 1 ;;
        *) return 0 ;;
    esac
}

# Probe SN via n2n REGISTER_SUPER business-layer check (UDP)
# Builds a minimal REGISTER_SUPER packet (n2n v2.3/v3 wire format, 42 bytes:
# common header 20B + register payload 22B) and sends it with netcat -u.
# A live SN always answers REGISTER_SUPER with ACK(6)/NAK(7), so receiving
# ANY reply >= 2 bytes proves it responds to n2n registrations — we do NOT
# need to byte-compare the reply (that was why od/cmp/dd were required before).
# Only needs: nc/netcat + printf + wc -c (utilities present on embedded builds)
#
# Return codes:
#   0 = alive (reply received)
#   1 = dead (no reply within timeout)
#   2 = skipped (nc/netcat missing; this layer does NOT participate in the
#       verdict, so the caller keeps the TCP verdict instead of failing the SN)
probe_sn_udp() {
    host="$1"
    port="$2"
    timeout="$3"
    community="$4"

    NC_BIN=""
    if type netcat >/dev/null 2>&1; then
        NC_BIN="netcat"
    elif type nc >/dev/null 2>&1; then
        NC_BIN="nc"
    else
        [ "$UDP_SKIP_WARNED" = "1" ] || log_warn "no nc/netcat found, UDP n2n probe skipped (falling back to tcp-only)"
        UDP_SKIP_WARNED=1
        return 2
    fi

    # Community padded (or truncated) to exactly 16 bytes (this codebase/v2.3 SN)
    clen=${#community}
    [ $clen -gt 16 ] && community=$(printf '%s' "$community" | cut -c1-16) && clen=16
    pad=$((16 - clen))

    # Cookie: 4 raw bytes from the low 32 bits of epoch seconds
    c=$(date +%s)
    c0=$((c & 255))
    c1=$(((c >> 8) & 255))
    c2=$(((c >> 16) & 255))
    c3=$(((c >> 24) & 255))

    pkt="/tmp/renewsn_pkt_$$"
    out="/tmp/renewsn_out_$$"

    # Build the raw REGISTER_SUPER packet (see _encode of wire.c):
    #   common: version(1)=2 + ttl(1)=255 + flags(2)=type5(REGISTER_SUPER) + community(16)
    #   reg:    cookie(4) + edgeMac(6)=0 + net_addr(4)=0(auto) + net_bitlen(1)=0
    #           + num_local(1)=0 + aflags(2)=0 + scheme(2)=0 + toksize(2)=0
    # Total 42 bytes. All multi-byte fields are big-endian (network byte order).
    # A live SN replies with ACK(6)/NAK(7) >= 4 bytes.
    {
        printf '\002\377'                     # version=2, ttl=255
        printf '\000\005'                     # flags=5 big-endian (REGISTER_SUPER)
        printf '%s' "$community"
        i=0
        while [ $i -lt $pad ]; do printf '\000'; i=$((i + 1)); done
        # cookie in big-endian (network byte order)
        printf "\\$(printf '%03o' "$c3")\\$(printf '%03o' "$c2")\\$(printf '%03o' "$c1")\\$(printf '%03o' "$c0")"
        printf '\000\000\000\000\000\000'     # edgeMac = 00:00:00:00:00:00
        printf '\000\000\000\000\000\000\000\000\000\000\000\000' # dev_addr(4)/net_bitlen(1)/num_local(1)/aflags(2)/scheme(2)/toksize(2) = 0
    } > "$pkt"

    # Run netcat in background (UDP mode). $! is the netcat process itself.
    # Note: NO -n flag — candidates are usually hostnames (e.g. n2n.moyann.com),
    # and -n forbids DNS resolution, making netcat fail immediately on a domain.
    "$NC_BIN" -u -w "$timeout" "$host" "$port" < "$pkt" > "$out" 2>/dev/null &
    ncid=$!

    # Watchdog: hard-kill netcat after timeout+2s in case some nc ignores -w
    ( sleep "$((timeout + 2))"; kill "$ncid" 2>/dev/null ) &
    wdog=$!
    wait "$ncid" 2>/dev/null
    kill "$wdog" 2>/dev/null

    # Any reply >= 2 bytes proves the SN answered the registration.
    n=$(wc -c < "$out" 2>/dev/null)
    rm -f "$pkt" "$out"

    if [ "${n:-0}" -ge 2 ]; then
        return 0                          # got a reply: SN responded to REGISTER_SUPER
    fi
    [ "$UDP_DIAG" = "1" ] && log_warn "UDP probe $host:$port got ${n:-0} bytes back"
    return 1
}

# ============================================================
# DNSPod API (using wget instead of curl)
# ============================================================

# Call DNSPod API via wget POST
# Usage: dnspod_call <api_method> <data>
dnspod_call() {
    method="$1"
    data="$2"
    
    wget -q -O - -T 10 --post-data="login_token=$DNS_TOKEN&format=json&$data" \
        "https://dnsapi.cn/$method" 2>/dev/null
}

# List all TXT record IDs for our sub-domain.
# Returns one record id per line (empty if none exists).
# Note: Record.List JSON starts with the domain object, so the FIRST "id":"..."
# is the domain id — it is skipped; the remaining ids are the actual records.
list_txt_record_ids() {
    result=$(dnspod_call "Record.List" "domain=$DNS_DOMAIN&sub_domain=$DNS_SUB_DOMAIN&record_type=TXT")
    echo "$result" | grep -o '"id":"[^"]*"' | tail -n +2 | cut -d'"' -f4
}

# Keep exactly ONE TXT record for our sub-domain: the smallest id wins, all
# duplicates are removed. This converges to a single record even when several
# machines run renewsn concurrently — every machine removes the copies it
# does not own, so the set always collapses back to one entry.
# Returns the surviving record id (empty if no record exists yet).
dedupe_txt_records() {
    ids=$(list_txt_record_ids)
    [ -z "$ids" ] && return 1   # no record yet — caller creates one

    keep=$(echo "$ids" | sort -n | head -1)
    for id in $ids; do
        if [ "$id" != "$keep" ]; then
            dnspod_call "Record.Remove" "domain=$DNS_DOMAIN&record_id=$id" >/dev/null
            log_info "Removed duplicate TXT record id=$id"
        fi
    done
    echo "$keep"
    return 0
}

# Update TXT record
update_txt() {
    value="$1"

    record_id=$(dedupe_txt_records)

    if [ -n "$record_id" ]; then
        log_info "Updating TXT record $DNS_SUB_DOMAIN.$DNS_DOMAIN = $value"
        result=$(dnspod_call "Record.Modify" \
            "domain=$DNS_DOMAIN&record_id=$record_id&sub_domain=$DNS_SUB_DOMAIN&record_type=TXT&value=$value&record_line=%E9%BB%98%E8%AE%A4&ttl=$DNS_TTL")
        if echo "$result" | grep -q '"code":"1"'; then
            log_info "DNS update successful"
            return 0
        else
            log_error "DNS update failed: $result"
            return 1
        fi
    else
        log_info "Creating TXT record $DNS_SUB_DOMAIN.$DNS_DOMAIN = $value"
        result=$(dnspod_call "Record.Create" \
            "domain=$DNS_DOMAIN&sub_domain=$DNS_SUB_DOMAIN&record_type=TXT&value=$value&record_line=%E9%BB%98%E8%AE%A4&ttl=$DNS_TTL")
        if echo "$result" | grep -q '"code":"1"'; then
            log_info "DNS record created successfully"
            return 0
        else
            log_error "DNS record creation failed: $result"
            return 1
        fi
    fi
}

# ============================================================
# Main loop
# ============================================================

log_info "renewsn started (interval=${INTERVAL}s)"

LAST_DNS_UPDATE=0
MIN_DNS_INTERVAL=60
LAST_DNS_VALUE=""
UDP_SKIP_WARNED=""  # one-shot flag, so a missing-tool warning is printed only once

# Per-candidate consecutive failure counters (debounce), indexed by position
# in CANDIDATES (1-based). Counter names are FAIL_CNT_<n> — simple digits,
# because candidate strings like "host:port" are not valid shell identifiers.
idx=0
for candidate in $CANDIDATES; do
    idx=$((idx + 1))
    eval "FAIL_CNT_$idx=0"
done
NUM_CAND=$idx

while true; do
    LOOP_START=$(date +%s)
    
    BEST_SN=""
    BEST_LATENCY=""
    
    # Probe all candidates
    idx=0
    for candidate in $CANDIDATES; do
        idx=$((idx + 1))
        host="${candidate%%:*}"
        port="${candidate##*:}"

        # TCP probe (only when method=tcp or both)
        tcp_ok=1; udp_ok=1
        if [ "$PROBE_METHOD" = "tcp" ] || [ "$PROBE_METHOD" = "both" ]; then
            if probe_sn_tcp "$host" "$port" "$PROBE_TIMEOUT"; then
                tcp_ok=1
            else
                tcp_ok=0
            fi
        fi

        # UDP n2n business-layer probe (default method: udp).
        # rc=2 means the layer was skipped for missing tools — it does NOT fail
        # the SN, so udp_ok stays 1 and the other layer's verdict decides.
        if [ "$PROBE_METHOD" = "udp" ] || [ "$PROBE_METHOD" = "both" ]; then
            probe_sn_udp "$host" "$port" "$PROBE_TIMEOUT" "$COMMUNITY"
            probe_udp_rc=$?
            if [ $probe_udp_rc -ne 1 ]; then
                udp_ok=1   # alive (0) or skipped (2): both pass the gate
            else
                udp_ok=0
            fi
        fi

        if [ $tcp_ok -eq 1 ] && [ $udp_ok -eq 1 ]; then
            # Probe passed: reset failure counter, candidate is usable now.
            eval "FAIL_CNT_$idx=0"
            alive=1
        else
            # Probe failed this round: increment the counter.
            eval "cur=\$FAIL_CNT_$idx"
            cur=$((cur + 1))
            eval "FAIL_CNT_$idx=$cur"
            if [ "$candidate" = "$LAST_DNS_VALUE" ] && \
               [ -n "$LAST_DNS_VALUE" ] && \
               [ "$cur" -lt "$FAIL_THRESHOLD" ]; then
                # Debounce: this is the SN currently in use — tolerate up to
                # FAIL_THRESHOLD-1 transient failures before switching away.
                alive=1
            else
                alive=0
            fi
        fi

        if [ $alive -eq 1 ] && [ -z "$BEST_SN" ]; then
            # Ordering follows the candidate list: the first usable one wins
            # (primary-first, no latency preference).
            BEST_SN="$candidate"
            BEST_LATENCY="0"
        fi
    done
    
    if [ -z "$BEST_SN" ]; then
        log_warn "No healthy supernode found"
        log_warn "If all candidates fail in udp mode, check COMMUNITY in renewsn.conf matches your edge's -c community"
        sleep "$INTERVAL"
        continue
    fi
    
    NOW=$(date +%s)
    DNS_ELAPSED=$((NOW - LAST_DNS_UPDATE))
    
    if [ "$BEST_SN" != "$LAST_DNS_VALUE" ] && [ "$DNS_ELAPSED" -ge "$MIN_DNS_INTERVAL" ]; then
        if [ -n "$DNS_TOKEN" ] && [ -n "$DNS_DOMAIN" ]; then
            log_info "Best SN: $BEST_SN"
            if update_txt "$BEST_SN"; then
                LAST_DNS_UPDATE=$NOW
                LAST_DNS_VALUE="$BEST_SN"
            fi
        else
            log_info "Best SN: $BEST_SN (DNS not configured)"
            LAST_DNS_VALUE="$BEST_SN"
        fi
    else
        log_info "Best SN: $BEST_SN (no DNS update needed)"
    fi
    
    # Sleep for remaining interval time
    LOOP_ELAPSED=$(($(date +%s) - LOOP_START))
    SLEEP_TIME=$((INTERVAL - LOOP_ELAPSED))
    [ "$SLEEP_TIME" -lt 1 ] && SLEEP_TIME=1
    sleep "$SLEEP_TIME"
done