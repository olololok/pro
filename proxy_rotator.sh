#!/bin/bash
# =============================================
#  XRAY AUTO-PROXY | FULL MULTI-PROTOCOL
#  vmess / vless / trojan / shadowsocks
#  Generates 10 SOCKS5 proxies on ports 1080–1089
#
#  Works in: SLAX, Debian Live, BusyBox
# =============================================

XRAY_BIN="/usr/local/bin/xray"
# SOURCE_URL removed in favor of dynamic API fetching

TOTAL_STREAMS=10
BASE_PORT=1080

# MONITORING CONFIG
CHECK_INTERVAL=15          # Check every 15s
DEAD_THRESHOLD=45          # If no ESTAB for 45s -> Restart

WORKDIR="."
LOG="./xray_auto.log"
LOCK="/tmp/xray_lock"
IPLOCK="$WORKDIR/iplock"
CONFDIR="$WORKDIR/xconfs"
RUNDIR="$WORKDIR/run"

mkdir -p "$CONFDIR" "$RUNDIR"

echo "[START] $(date)" >> "$LOG"

# ========== XRAY Check ==========
if [ ! -x "$XRAY_BIN" ]; then
    echo "[FATAL] XRay binary missing: $XRAY_BIN" | tee -a "$LOG"
    echo "Please download XRay from https://github.com/XTLS/Xray-core/releases"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "[FATAL] jq is missing. Please install it (apt install jq)" | tee -a "$LOG"
    exit 1
fi

if ! command -v shuf &> /dev/null; then
    echo "[WARN] shuf is missing. Installing coreutils or using sort -R fallback..." | tee -a "$LOG"
    # Fallback function if needed or just warn
fi

# ========== Cleanup & Lock ==========
cleanup() {
    echo "[*] Cleaning up old processes and locks..."
    pkill -f "$XRAY_BIN"
    pkill -f "xray_auto"
    rm -f "$LOCK"
    rm -f "$IPLOCK"/*
}

# Force cleanup on start
cleanup

touch "$LOCK"
trap 'rm -f "$LOCK"; pkill -P $$' EXIT


# Auto-detect curl
CURL_BIN="curl"
if command -v curl.exe &>/dev/null; then
    CURL_BIN="curl.exe"
fi

# ================================================================
echo "[*] Generating random config URLs (Bypassing API)..." | tee -a "$LOG"

echo -n "" > all_links.txt

# ================================================================
#  DOWNLOAD CONFIGS (DEPRECATED - FETCH PER STREAM)
# ================================================================
# We no longer download all links at start. 
# Each stream fetches its own list from the repo.

# ================================================================
#   UNIQUE IP SYSTEM (Psiphon-style)
# ================================================================
mkdir -p "$IPLOCK"

clear_ip() {
    local ID="$1"
    rm -f "$IPLOCK/ip_$ID"
}

set_ip() {
    local ID="$1"
    local IP="$2"

    for F in "$IPLOCK"/ip_*; do
        [ -f "$F" ] || continue
        if [ "$F" != "$IPLOCK/ip_$ID" ] && [ "$(cat "$F")" = "$IP" ]; then
            return 1
        fi
    done

    echo "$IP" > "$IPLOCK/ip_$ID"
    return 0
}



# ================================================================
#  PARSER | UNIVERSAL (VMESS / VLESS / TROJAN / SS)
# ================================================================
build_xray_config() {
    local LINK="$1"
    local PORT="$2"
    local CFG="$3"

    # Clean line
    LINK=$(echo "$LINK" | sed 's/#.*//g' | sed 's/\[.*//g' | tr -d ' ' | tr -d '\r')

    local TYPE=$(echo "$LINK" | cut -d':' -f1)

    case "$TYPE" in

    # --------------------------------------------------------------
    #  VMESS
    # --------------------------------------------------------------
    vmess)
        DATA=${LINK#vmess://}

        # Base64 check
        if echo "$DATA" | grep -Eq '^[A-Za-z0-9+/=]+$'; then
            JSON=$(echo "$DATA" | base64 -d 2>/dev/null)
        else
            # URL FORMAT → vmess://uuid@host:port?params
            UUID=$(echo "$DATA" | cut -d'@' -f1)
            HOST=$(echo "$DATA" | cut -d'@' -f2 | cut -d':' -f1)
            PORT_R=$(echo "$DATA" | cut -d':' -f2 | cut -d'?' -f1)
            WS_PATH=$(echo "$DATA" | grep -o "path=[^&]*" | cut -d= -f2)
            HOST_H=$(echo "$DATA" | grep -o "host=[^&]*" | cut -d= -f2)

            JSON=$(cat <<EOF
{"add":"$HOST","port":"$PORT_R","id":"$UUID","aid":"0","net":"ws","path":"$WS_PATH","host":"$HOST_H"}
EOF
)
        fi

        ADD=$(echo "$JSON" | jq -r '.add' 2>/dev/null)
        PR=$(echo "$JSON" | jq -r '.port' 2>/dev/null)
        XID=$(echo "$JSON" | jq -r '.id' 2>/dev/null)
        NET=$(echo "$JSON" | jq -r '.net // "tcp"')

        # Debug failure
        if [ -z "$ADD" ] || [ -z "$PR" ] || [ -z "$XID" ]; then
             echo "[DEBUG] Stream failed vmess parsing. ADD=$ADD PR=$PR ID=$XID"
             return 1
        fi

        WS_PATH=$(echo "$JSON" | jq -r '.path // ""')
        HOST_H=$(echo "$JSON" | jq -r '.host // ""')

        cat > "$CFG" <<EOF
{
 "log": { "loglevel": "none" },
 "inbounds":[{"port":$PORT,"listen":"127.0.0.1","protocol":"socks"}],
 "outbounds":[{
   "protocol":"vmess",
   "settings":{"vnext":[{"address":"$ADD","port":$PR,"users":[{"id":"$XID","alterId":0}]}]},
   "streamSettings":{
       "network":"$NET",
       "wsSettings":{"path":"$WS_PATH","headers":{"Host":"$HOST_H"}}
   }
 }]
}
EOF
    ;;

    # --------------------------------------------------------------
    #  VLESS
    # --------------------------------------------------------------
    vless)
        DATA=${LINK#vless://}
        HOST=$(echo "$DATA" | cut -d'@' -f2 | cut -d':' -f1)
        UUID=$(echo "$DATA" | cut -d'@' -f1)
        PORT_R=$(echo "$DATA" | cut -d':' -f2 | cut -d'?' -f1)
        NET="ws"
        WS_PATH=$(echo "$DATA" | grep -o "path=[^&]*" | cut -d= -f2)

        [ -z "$HOST" ] || [ -z "$PORT_R" ] || [ -z "$UUID" ] && return 1

        cat > "$CFG" <<EOF
{
 "log": { "loglevel": "none" },
 "inbounds":[{"port":$PORT,"listen":"127.0.0.1","protocol":"socks"}],
 "outbounds":[{
   "protocol":"vless",
   "settings":{"vnext":[{"address":"$HOST","port":$PORT_R,"users":[{"id":"$UUID","encryption":"none"}]}]},
   "streamSettings":{"network":"ws","wsSettings":{"path":"$WS_PATH"}}
 }]
}
EOF
    ;;

    # --------------------------------------------------------------
    #  TROJAN
    # --------------------------------------------------------------
    trojan)
        DATA=${LINK#trojan://}
        PASS=$(echo "$DATA" | cut -d'@' -f1)
        HOST=$(echo "$DATA" | cut -d'@' -f2 | cut -d':' -f1)
        PORT_R=$(echo "$DATA" | cut -d':' -f2 | cut -d'?' -f1)

        [ -z "$PASS" ] || [ -z "$HOST" ] || [ -z "$PORT_R" ] && return 1

        cat > "$CFG" <<EOF
{
 "log": { "loglevel": "none" },
 "inbounds":[{"port":$PORT,"listen":"127.0.0.1","protocol":"socks"}],
 "outbounds":[{
   "protocol":"trojan",
   "settings":{"servers":[{"address":"$HOST","port":$PORT_R,"password":"$PASS"}]}
 }]
}
EOF
    ;;

    # --------------------------------------------------------------
    #  SHADOWSOCKS
    # --------------------------------------------------------------
    ss)
        DATA=${LINK#ss://}
        BASE=$(echo "$DATA" | cut -d'@' -f1)
        HOST=$(echo "$DATA" | cut -d'@' -f2 | cut -d':' -f1)
        PORT_R=$(echo "$DATA" | cut -d':' -f2)

        DECODE=$(echo "$BASE" | sed 's/%3D/=/g; s/%2B/+/g; s/%2F/\//g' | base64 -d 2>/dev/null)
        METHOD=$(echo "$DECODE" | cut -d':' -f1)
        PASS=$(echo "$DECODE" | cut -d':' -f2)

        [ -z "$METHOD" ] || [ -z "$PASS" ] || [ -z "$HOST" ] || [ -z "$PORT_R" ] && return 1

        # CHECK FOR DEPRECATED CIPHERS (Xray v1.8+ / v25+ dropped these)
        if [[ "$METHOD" == *"cfb"* ]] || [[ "$METHOD" == *"rc4"* ]]; then
             echo "[DEBUG] Skipping deprecated cipher: $METHOD"
             return 1
        fi

        cat > "$CFG" <<EOF
{
 "log": { "loglevel": "none" },
 "inbounds":[{"port":$PORT,"listen":"127.0.0.1","protocol":"socks"}],
 "outbounds":[{
   "protocol":"shadowsocks",
   "settings":{"servers":[{"address":"$HOST","port":$PORT_R,"method":"$METHOD","password":"$PASS"}]}
 }]
}
EOF
    ;;

    *) return 1 ;;
    esac

    return 0
}



# ================================================================
#   LAUNCH STREAM
# ================================================================
start_stream() {
    local ID="$1"
    local PORT="$2"

    clear_ip "$ID"
    CFG="$CONFDIR/x_$ID.json"

    echo "[*] Starting stream $ID on 127.0.0.1:$PORT…" | tee -a "$LOG"

    # Randomly pick a list number 1-20
    # Use shuf to pick a number
    RAND_LIST_NUM=$(shuf -i 1-20 -n 1)
    
    # URL for the list in the repo
    REPO_URL="https://raw.githubusercontent.com/olololok/pro/main/proxy_lists/list_${RAND_LIST_NUM}.txt"
    
    LIST_FILE="$WORKDIR/links_$ID.txt"
    
    echo "   -> Stream $ID fetching $REPO_URL"
    $CURL_BIN -skL --connect-timeout 10 --retry 2 "$REPO_URL" > "$LIST_FILE"
    
    # Validation
    if [ ! -s "$LIST_FILE" ] || grep -q "404: Not Found" "$LIST_FILE"; then
         echo "[!] Stream $ID: Failed to download list $RAND_LIST_NUM or empty." | tee -a "$LOG"
         sleep 10
         return
    fi

    # Flatten logic - just read from the downloaded list
    # We shuffle the lines in place so we don't always start from top
    shuf "$LIST_FILE" -o "$LIST_FILE"

    while read LINK; do
        build_xray_config "$LINK" "$PORT" "$CFG" || { sleep 0.1; continue; }

        pkill -f "$CFG" 2>/dev/null
        # Run Xray with config, output to screen AND file (as requested)
        "$XRAY_BIN" run -c "$CFG" 2>&1 | tee "$WORKDIR/xray_error_$ID.log" &
        XRAY_PID=$!

        sleep 5
        
        # Check if Xray died immediately
        if ! kill -0 $XRAY_PID 2>/dev/null; then
             echo "[!] Stream $ID: Xray crashed immediately. Check log above."
             continue
        fi

        # Check IP via proxy
        IP=$($CURL_BIN --socks5-hostname 127.0.0.1:$PORT -s -m 6 https://checkip.amazonaws.com | tr -d '\r')

        if [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if set_ip "$ID" "$IP"; then
                echo "[✓] Stream $ID → IP $IP (PID: $XRAY_PID)" | tee -a "$LOG"
                # Keep running until it dies/fails monitor
                return
            else
                echo "[x] Stream $ID: duplicate IP $IP" | tee -a "$LOG"
            fi
        else
            echo "[x] Stream $ID: bad connection" | tee -a "$LOG"
        fi

        # Kill invalid process
        kill $XRAY_PID 2>/dev/null
        pkill -f "$CFG"
    done < "$LIST_FILE"

    echo "[!] Stream $ID: exhausted list $RAND_LIST_NUM" | tee -a "$LOG"
}


# ================================================================
#   MONITOR 9HITS
# ================================================================
check_9hits() {
    if pgrep -f "9hits" >/dev/null; then
        return 0
    else
        return 1
    fi
}

monitor_9hits() {
    echo "[*] Starting 9Hits monitor..." | tee -a "$LOG"
    while true; do
        sleep 20

        if ! check_9hits; then
            echo "[!] 9Hits NOT running! Restarting..." | tee -a "$LOG"
            bash /tmp/ok.sh
            # Wait a bit for it to start
            sleep 10
        fi
    done
}

# ================================================================
#   MONITOR STREAM (ESTAB CHECK)
# ================================================================
monitor_stream() {
    local ID="$1"
    local PORT="$2"
    local NO_ESTAB_TIME=0

    while true; do
        sleep $CHECK_INTERVAL

        # Check for ESTABLISHED connection on the local port
        # Fallback to netstat if ss is missing (Windows compatibility)
        ESTABLISHED=0
        if command -v ss >/dev/null; then
             if ss -ntp | grep -q ":$PORT " | grep -q "ESTAB"; then
                 ESTABLISHED=1
             fi
        else
             # Windows / No ss -> use netstat
             # netstat -an output: TCP 127.0.0.1:1081 ... ESTABLISHED
             if netstat -an | grep -q ":$PORT " | grep -q "ESTAB"; then
                 ESTABLISHED=1
             fi
        fi

        if [ "$ESTABLISHED" -eq 1 ]; then
            NO_ESTAB_TIME=0
        else
            NO_ESTAB_TIME=$((NO_ESTAB_TIME + CHECK_INTERVAL))
        fi

        if (( NO_ESTAB_TIME >= DEAD_THRESHOLD )); then
            echo "[DEAD] Stream $ID: No ESTAB > $DEAD_THRESHOLD sec. Restarting..." | tee -a "$LOG"
            
            # Kill process using this config
            pkill -f "x_$ID.json"
            
            # Restart
            start_stream "$ID" "$PORT"
            NO_ESTAB_TIME=0
        fi
    done
}

# ================================================================
#  MAIN LOOP
# ================================================================
# Kill old instances
pkill -f "xconfs/x_"

# Start 9Hits Monitor in background
monitor_9hits &

for ID in $(seq 1 $TOTAL_STREAMS); do
    PORT=$((BASE_PORT + ID))
    (
        start_stream "$ID" "$PORT"
        monitor_stream "$ID" "$PORT"
    ) &
    sleep 1 # Small stagger to prevent CPU spike
done

echo "[*] All streams initialized. Monitoring..."
wait
