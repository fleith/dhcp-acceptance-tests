#!/bin/sh
set -e

IFACE="${1:-eth0}"
DHCPV6_SUBNET="${DHCPV6_SUBNET:-fd00:29::/64}"
DHCPV6_POOL="${DHCPV6_POOL:-fd00:29::100 - fd00:29::1ff}"
DHCPV6_DNS="${DHCPV6_DNS:-2001:4860:4860::8888}"
DHCPV6_DOMAIN_SEARCH="${DHCPV6_DOMAIN_SEARCH:-example.test}"
DHCPV6_PD_PREFIX="${DHCPV6_PD_PREFIX:-fd00:30::}"
DHCPV6_PD_PREFIX_LEN="${DHCPV6_PD_PREFIX_LEN:-60}"
DHCPV6_PD_DELEGATED_LEN="${DHCPV6_PD_DELEGATED_LEN:-64}"
DHCPV6_PREFERENCE="${DHCPV6_PREFERENCE:-}"
DHCPV6_RAPID_COMMIT="${DHCPV6_RAPID_COMMIT:-1}"
DHCPV6_DDNS_MANAGER_IP="${DHCPV6_DDNS_MANAGER_IP:-127.0.0.1}"
DHCPV6_DDNS_MANAGER_PORT="${DHCPV6_DDNS_MANAGER_PORT:-53001}"
DHCPV6_DDNS_SUFFIX="${DHCPV6_DDNS_SUFFIX:-dhcp-acceptance.test}"
DHCPV6_RENEW_TIMER="${DHCPV6_RENEW_TIMER:-60}"
DHCPV6_REBIND_TIMER="${DHCPV6_REBIND_TIMER:-105}"
DHCPV6_PREFERRED_LIFETIME="${DHCPV6_PREFERRED_LIFETIME:-120}"
DHCPV6_VALID_LIFETIME="${DHCPV6_VALID_LIFETIME:-120}"
DHCPV6_RECLAIM_TIMER_WAIT="${DHCPV6_RECLAIM_TIMER_WAIT:-10}"
DHCPV6_INTERFACE_ID_POLICY="${DHCPV6_INTERFACE_ID_POLICY:-0}"
DHCPV6_INTERFACE_ID_A_HEX="${DHCPV6_INTERFACE_ID_A_HEX:-00ff706f72742d418000}"
DHCPV6_INTERFACE_ID_B_HEX="${DHCPV6_INTERFACE_ID_B_HEX:-817669662d42007f}"
DHCPV6_INTERFACE_ID_POOL_A="${DHCPV6_INTERFACE_ID_POOL_A:-fd00:29::100 - fd00:29::17f}"
DHCPV6_INTERFACE_ID_POOL_B="${DHCPV6_INTERFACE_ID_POOL_B:-fd00:29::180 - fd00:29::1ff}"
DHCPV6_POOLS_JSON="${DHCPV6_POOLS_JSON:-}"
DHCPV6_SERVER_LOG_FILE="${DHCPV6_SERVER_LOG_FILE:-}"
DHCPV6_LOG_SEVERITY="${DHCPV6_LOG_SEVERITY:-INFO}"
DHCPV6_LOG_DEBUGLEVEL="${DHCPV6_LOG_DEBUGLEVEL:-0}"

case "$DHCPV6_RAPID_COMMIT" in
    1) RAPID_COMMIT_JSON=true ;;
    0) RAPID_COMMIT_JSON=false ;;
    *)
        echo "[kea6] ERROR: DHCPV6_RAPID_COMMIT must be 0 or 1" >&2
        exit 1
        ;;
esac

validate_interface_id_hex() {
    value="$1"
    name="$2"
    if ! printf '%s' "$value" | grep -Eq '^[0-9a-fA-F]+$' || [ $(( ${#value} % 2 )) -ne 0 ]; then
        echo "[kea6] ERROR: $name must contain an even number of hexadecimal digits" >&2
        exit 1
    fi
}

CLIENT_CLASSES_OPTION=''
POOLS_JSON='[ { "pool": "'"$DHCPV6_POOL"'" } ]'
if [ -n "$DHCPV6_POOLS_JSON" ]; then
    POOLS_JSON="$DHCPV6_POOLS_JSON"
fi
case "$DHCPV6_INTERFACE_ID_POLICY" in
    0) ;;
    1)
        validate_interface_id_hex "$DHCPV6_INTERFACE_ID_A_HEX" DHCPV6_INTERFACE_ID_A_HEX
        validate_interface_id_hex "$DHCPV6_INTERFACE_ID_B_HEX" DHCPV6_INTERFACE_ID_B_HEX
        CLIENT_CLASSES_OPTION='"client-classes": [
      {
        "name": "rfc9915-interface-a",
        "test": "relay6[-1].option[18].hex == 0x'"$DHCPV6_INTERFACE_ID_A_HEX"'"
      },
      {
        "name": "rfc9915-interface-b",
        "test": "relay6[-1].option[18].hex == 0x'"$DHCPV6_INTERFACE_ID_B_HEX"'"
      }
    ],'
        POOLS_JSON='[
          {
            "pool": "'"$DHCPV6_INTERFACE_ID_POOL_A"'",
            "client-classes": [ "rfc9915-interface-a" ]
          },
          {
            "pool": "'"$DHCPV6_INTERFACE_ID_POOL_B"'",
            "client-classes": [ "rfc9915-interface-b" ]
          }
        ]'
        ;;
    *)
        echo "[kea6] ERROR: DHCPV6_INTERFACE_ID_POLICY must be 0 or 1" >&2
        exit 1
        ;;
esac

PREFERENCE_OPTION=""
if [ -n "$DHCPV6_PREFERENCE" ]; then
    PREFERENCE_OPTION=',
          { "name": "preference", "data": "'"$DHCPV6_PREFERENCE"'" }'
fi

LOGGER_OUTPUT_OPTIONS='[ { "output": "stdout" } ]'
if [ -n "$DHCPV6_SERVER_LOG_FILE" ]; then
    mkdir -p "$(dirname "$DHCPV6_SERVER_LOG_FILE")"
    : > "$DHCPV6_SERVER_LOG_FILE"
    LOGGER_OUTPUT_OPTIONS='[ { "output": "stdout" }, { "output": "'"$DHCPV6_SERVER_LOG_FILE"'", "flush": true } ]'
fi

if ! ip -6 addr show "$IFACE" | grep -q "scope global"; then
    echo "[kea6] ERROR: No global IPv6 address on $IFACE" >&2
    exit 1
fi

# Kea derives a link-local from the interface MAC and binds UDP/547 to it.
# Docker may still be running duplicate-address detection when this entrypoint
# starts, so ensure the expected EUI-64 address exists and is ready before Kea.
MAC=$(cat "/sys/class/net/$IFACE/address")
IFS=: read -r m1 m2 m3 m4 m5 m6 << EOF
$MAC
EOF
m1_flipped=$(printf "%02x" $(( 0x$m1 ^ 0x02 )))
KEA_LL="fe80::${m1_flipped}${m2}:${m3}ff:fe${m4}:${m5}${m6}"
ip -6 addr add "${KEA_LL}/64" dev "$IFACE" nodad >/dev/null 2>&1 || true

link_local_ready() {
    ip -6 -o addr show dev "$IFACE" to "${KEA_LL}/128" | awk '
        $3 == "inet6" && index($0, " tentative") == 0 && index($0, " dadfailed") == 0 { found = 1 }
        END { exit !found }
    '
}

for i in $(seq 1 50); do
    if link_local_ready; then
        break
    fi
    sleep 0.2
done

if ! link_local_ready; then
    echo "[kea6] ERROR: Link-local address $KEA_LL did not become usable on $IFACE" >&2
    ip -6 addr show dev "$IFACE" >&2
    exit 1
fi

mkdir -p /etc/kea /data /run/kea /var/run/kea /var/lib/kea
rm -f /run/kea/*.pid /var/run/kea/*.pid
cat > /etc/kea/kea-dhcp6.conf << CONF
{
  "Dhcp6": {
    "interfaces-config": {
      "interfaces": [ "$IFACE" ]
    },
    $CLIENT_CLASSES_OPTION
    "dhcp-ddns": {
      "enable-updates": true,
      "server-ip": "$DHCPV6_DDNS_MANAGER_IP",
      "server-port": $DHCPV6_DDNS_MANAGER_PORT
    },
    "ddns-send-updates": true,
    "ddns-qualifying-suffix": "$DHCPV6_DDNS_SUFFIX",
    "lease-database": {
      "type": "memfile",
      "name": "/var/lib/kea/kea-leases6.csv",
      "persist": true
    },
    "renew-timer": $DHCPV6_RENEW_TIMER,
    "rebind-timer": $DHCPV6_REBIND_TIMER,
    "preferred-lifetime": $DHCPV6_PREFERRED_LIFETIME,
    "valid-lifetime": $DHCPV6_VALID_LIFETIME,
    "expired-leases-processing": {
      "reclaim-timer-wait-time": $DHCPV6_RECLAIM_TIMER_WAIT,
      "flush-reclaimed-timer-wait-time": 25,
      "hold-reclaimed-time": 0,
      "max-reclaim-leases": 100,
      "max-reclaim-time": 250,
      "unwarned-reclaim-cycles": 5
    },
    "subnet6": [
      {
        "id": 1,
        "subnet": "$DHCPV6_SUBNET",
        "interface": "$IFACE",
        "rapid-commit": $RAPID_COMMIT_JSON,
        "pools": $POOLS_JSON,
        "pd-pools": [
          {
            "prefix": "$DHCPV6_PD_PREFIX",
            "prefix-len": $DHCPV6_PD_PREFIX_LEN,
            "delegated-len": $DHCPV6_PD_DELEGATED_LEN
          }
        ],
        "option-data": [
          { "name": "dns-servers", "data": "$DHCPV6_DNS" },
          { "name": "domain-search", "data": "$DHCPV6_DOMAIN_SEARCH" }$PREFERENCE_OPTION
        ]
      }
    ],
    "loggers": [
      {
        "name": "kea-dhcp6",
        "output_options": $LOGGER_OUTPUT_OPTIONS,
        "severity": "$DHCPV6_LOG_SEVERITY",
        "debuglevel": $DHCPV6_LOG_DEBUGLEVEL
      }
    ]
  }
}
CONF

echo "[kea6] interface=$IFACE subnet=$DHCPV6_SUBNET pool=$DHCPV6_POOL pd=$DHCPV6_PD_PREFIX/$DHCPV6_PD_PREFIX_LEN->$DHCPV6_PD_DELEGATED_LEN link_local=$KEA_LL interface_id_policy=$DHCPV6_INTERFACE_ID_POLICY"
echo "[kea6] Generated /etc/kea/kea-dhcp6.conf:"
cat /etc/kea/kea-dhcp6.conf

echo "[kea6] Interface addresses:"
ip -6 addr show dev "$IFACE"

exec kea-dhcp6 -c /etc/kea/kea-dhcp6.conf
