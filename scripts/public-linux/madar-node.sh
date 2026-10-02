#!/usr/bin/env bash
# MADAR node for Linux (x86-64) — a regular node that verifies blocks and does not vote. Same settings as the Windows app.
# MADAR Node for Linux (x86-64) — a normal full node that verifies blocks and does not vote.
#
#   ./madar-node.sh start  [--name NAME] [--help-network]   run in background
#   ./madar-node.sh stop                                      stop
#   ./madar-node.sh status                                    status
#   ./madar-node.sh log                                       follow the log
#   ./madar-node.sh service [--name NAME]                     autostart at login (systemd user unit)
set -eu

DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
BIN="$DIR/madar-node"
SPEC="$DIR/madar-spec.json"
DATA="${MADAR_DATA:-$HOME/.local/share/madar-node}"
LOG="$DATA/node.log"
PIDF="$DATA/node.pid"
CONF="$DATA/name"
RPC="${MADAR_RPC_PORT:-9944}"
P2P="${MADAR_P2P_PORT:-30333}"
PROM="${MADAR_PROM_PORT:-9615}"
GENESIS=0xec491025ce422aebac0a5e20fb4c868bb3dacefe56cb051060492ceedd6f5e5c
BOOT1=/ip4/188.241.241.253/tcp/30333/p2p/12D3KooWDAr7FDtAeUx51zowWytNKeeuQfB5B2cyF4bZmDEp9j9K
BOOT2=/ip4/103.254.60.222/tcp/30333/p2p/12D3KooWQqcRoYDfHLGrj7kUcNFQHnHvpcgZvKMfU1RuPRqnhuXS

mkdir -p "$DATA"

running() { [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; }

node_args() {
    local name="$1" listen="/ip4/127.0.0.1/tcp/$P2P" inpeers=8
    if [ "${2:-}" = "help" ]; then listen="/ip4/0.0.0.0/tcp/$P2P"; inpeers=16; fi
    echo --chain "$SPEC" --base-path "$DATA/chain" --name "$name" \
        --bootnodes "$BOOT1" --bootnodes "$BOOT2" --listen-addr "$listen" \
        --rpc-port "$RPC" --rpc-methods safe --rpc-max-connections 10 --prometheus-port "$PROM" \
        --no-telemetry --no-mdns --in-peers "$inpeers" --out-peers 4 \
        --state-pruning 256 --blocks-pruning 4096 --db-cache 64 --trie-cache-size 67108864 \
        --pool-limit 1024 --pool-kbytes 4096 --max-runtime-instances 2
}

pick_name() {
    local name=""
    while [ $# -gt 0 ]; do [ "$1" = "--name" ] && name="${2:-}"; shift; done
    [ -z "$name" ] && [ -f "$CONF" ] && name="$(cat "$CONF")"
    [ -z "$name" ] && name="madar-linux-$(head -c3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    printf '%s' "$name" | grep -Eq '^[A-Za-z0-9_-]{3,20}$' || { echo "name: 3–20 of A-Z a-z 0-9 _ -"; exit 2; }
    printf '%s' "$name" > "$CONF"
    echo "$name"
}

# A data folder from an old chain (different genesis) is moved aside automatically instead of the node getting stuck on it.
check_genesis() {
    local marker="$DATA/genesis"
    if [ -d "$DATA/chain" ] && [ "$(cat "$marker" 2>/dev/null)" != "$GENESIS" ]; then
        mv "$DATA/chain" "$DATA/chain-old-$(date +%Y%m%d%H%M%S)"
    fi
    echo "$GENESIS" > "$marker"
}

case "${1:-status}" in
    start)
        shift || true
        if running; then echo "already running (pid $(cat "$PIDF"))"; exit 0; fi
        help=""; for a in "$@"; do [ "$a" = "--help-network" ] && help=help; done
        name="$(pick_name "$@")"
        check_genesis
        [ -f "$LOG" ] && [ "$(stat -c %s "$LOG")" -gt 20971520 ] && mv "$LOG" "$LOG.1"
        # shellcheck disable=SC2046
        nohup "$BIN" $(node_args "$name" "$help") >>"$LOG" 2>&1 &
        echo $! > "$PIDF"
        echo "✅ node started «$name». log: $LOG"
        ;;
    stop)
        if running; then kill -INT "$(cat "$PIDF")"; echo "⏹ stopped"; else echo "not running"; fi
        rm -f "$PIDF"
        ;;
    status)
        if running; then
            echo "✅ running (pid $(cat "$PIDF"))"
            "$BIN" doctor --rpc "127.0.0.1:$RPC" --expect-role full --expected-genesis-hash "$GENESIS" --base-path "$DATA/chain" 2>/dev/null | tail -n 15 || true
        else
            echo "⏹ not running"
        fi
        ;;
    log) tail -n 40 -f "$LOG" ;;
    service)
        shift || true
        name="$(pick_name "$@")"
        mkdir -p "$HOME/.config/systemd/user"
        # shellcheck disable=SC2046
        cat > "$HOME/.config/systemd/user/madar-node.service" <<EOF
[Unit]
Description=MADAR Node (full node, does not vote)
After=network-online.target

[Service]
ExecStartPre=/bin/sh -c 'd="$DATA"; m="\$d/genesis"; if [ -d "\$d/chain" ] && [ "\$(cat "\$m" 2>/dev/null)" != "$GENESIS" ]; then mv "\$d/chain" "\$d/chain-old-\$(date +%%Y%%m%%d%%H%%M%%S)"; fi; echo $GENESIS > "\$m"'
ExecStart=$BIN $(node_args "$name")
Restart=on-failure
RestartSec=10
Nice=10

[Install]
WantedBy=default.target
EOF
        systemctl --user daemon-reload
        systemctl --user enable --now madar-node.service
        echo "✅ running now and at login. To stop: systemctl --user disable --now madar-node"
        echo "   (to run without login: sudo loginctl enable-linger $USER)"
        ;;
    *) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
