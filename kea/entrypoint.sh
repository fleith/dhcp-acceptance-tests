#!/bin/sh
set -e

IFACE="${1:-eth0}"

IP_PREFIX=$(ip -4 addr show "$IFACE" | awk '/inet / {print $2; exit}')
if [ -z "$IP_PREFIX" ]; then
    echo "[kea] ERROR: No IPv4 address on $IFACE" >&2
    exit 1
fi

IP="${IP_PREFIX%%/*}"
PREFIX="${IP_PREFIX##*/}"
ALT_SUBNET_CIDR="${RFC3011_ALT_SUBNET:-}"
RFC8925_WAIT="${RFC8925_WAIT:-1800}"
RFC3442_EXTRA_ROUTE_COUNT="${RFC3442_EXTRA_ROUTE_COUNT:-30}"
DHCPV4_RFC3396_POLICY_DOMAIN="${DHCPV4_RFC3396_POLICY_DOMAIN:-rfc3396-reassembled.test}"
DHCPV4_POOL_START_OFFSET="${DHCPV4_POOL_START_OFFSET:-100}"
DHCPV4_POOL_END_OFFSET="${DHCPV4_POOL_END_OFFSET:-200}"
DHCPV4_ALT_POOL_ENABLED="${DHCPV4_ALT_POOL_ENABLED:-1}"
DHCPV4_RESERVED_MAC="${DHCPV4_RESERVED_MAC:-02:00:00:ff:00:01}"
DHCPV4_RESERVED_OFFSET="${DHCPV4_RESERVED_OFFSET:-50}"
DHCPV4_CLASS_NAME="${DHCPV4_CLASS_NAME:-acceptance-class}"
DHCPV4_RELAY_SUBNET="${DHCPV4_RELAY_SUBNET:-172.29.2.0/24}"
DHCPV4_INJECT_OVERLAPPING_SUBNET="${DHCPV4_INJECT_OVERLAPPING_SUBNET:-0}"
DHCPV4_OVERLAP_ORDER="${DHCPV4_OVERLAP_ORDER:-primary-first}"
DHCPV4_FORCE_STORAGE_FAILURE="${DHCPV4_FORCE_STORAGE_FAILURE:-0}"
DHCPV4_PING_CHECK_ENABLED="${DHCPV4_PING_CHECK_ENABLED:-0}"
DHCPV4_PING_TIMEOUT_MS="${DHCPV4_PING_TIMEOUT_MS:-300}"
DHCPV4_PING_CHECK_ADDRESS="${DHCPV4_PING_CHECK_ADDRESS:-}"
DHCPV4_PING_CHECK_PEER_MAC="${DHCPV4_PING_CHECK_PEER_MAC:-02:42:ac:1d:00:03}"

prefix_to_netmask() {
    _p=$1
    _result=""
    _i=0
    while [ $_i -lt 4 ]; do
        if [ $_p -ge 8 ]; then
            _octet=255
            _p=$(( _p - 8 ))
        elif [ $_p -gt 0 ]; then
            _octet=$(( 256 - (1 << (8 - _p)) ))
            _p=0
        else
            _octet=0
        fi
        _result="${_result:+$_result.}$_octet"
        _i=$(( _i + 1 ))
    done
    echo "$_result"
}

NETMASK=$(prefix_to_netmask "$PREFIX")

IFS=. read -r i1 i2 i3 i4 << EOF
$IP
EOF
IFS=. read -r m1 m2 m3 m4 << EOF
$NETMASK
EOF
NET="$(( i1 & m1 )).$(( i2 & m2 )).$(( i3 & m3 )).$(( i4 & m4 ))"
NET3="$(echo "$NET" | cut -d. -f1-3)"

IFS=. read -r n1 n2 n3 n4 << EOF
$NET
EOF
if [ -z "$ALT_SUBNET_CIDR" ]; then
    ALT_SUBNET_CIDR="${n1}.${n2}.$(( n3 + 1 )).0/$PREFIX"
fi
ALT_NET="${ALT_SUBNET_CIDR%%/*}"
ALT_NET3="$(echo "$ALT_NET" | cut -d. -f1-3)"
ALT_ROUTER_IP="${ALT_NET3}.1"
RELAY_NET="${DHCPV4_RELAY_SUBNET%%/*}"
RELAY_NET3="$(echo "$RELAY_NET" | cut -d. -f1-3)"

ip route add "$DHCPV4_RELAY_SUBNET" dev "$IFACE" >/dev/null 2>&1 || true
if [ "$DHCPV4_PING_CHECK_ENABLED" = "1" ] && [ -n "$DHCPV4_PING_CHECK_ADDRESS" ]; then
    ip neigh replace "$DHCPV4_PING_CHECK_ADDRESS" \
        lladdr "$DHCPV4_PING_CHECK_PEER_MAC" nud permanent dev "$IFACE"
fi

OVERLAP_SUBNET_BEFORE=""
OVERLAP_SUBNET_AFTER=""
PRIMARY_OVERLAP_OPTION=""
if [ "$DHCPV4_INJECT_OVERLAPPING_SUBNET" = "1" ]; then
    OVERLAP_SUBNET_OBJECT="{ \"id\": 4, \"subnet\": \"$NET/25\", \"pools\": [ { \"pool\": \"${NET3}.10 - ${NET3}.20\" } ], \"option-data\": [ { \"name\": \"domain-name\", \"data\": \"overlap-specific.test\" } ] }"
    PRIMARY_OVERLAP_OPTION=',
          { "name": "domain-name", "data": "overlap-primary.test" }'
    case "$DHCPV4_OVERLAP_ORDER" in
        primary-first)
            OVERLAP_SUBNET_AFTER=", $OVERLAP_SUBNET_OBJECT"
            ;;
        specific-first)
            OVERLAP_SUBNET_BEFORE="$OVERLAP_SUBNET_OBJECT,"
            ;;
        *)
            echo "[kea] ERROR: DHCPV4_OVERLAP_ORDER must be primary-first or specific-first" >&2
            exit 1
            ;;
    esac
fi

LEASE_FILE=/var/lib/kea/kea-leases4.csv
if [ "$DHCPV4_FORCE_STORAGE_FAILURE" = "1" ]; then
    LEASE_FILE=/proc/kea-acceptance-leases.csv
fi

ALT_POOLS='[]'
if [ "$DHCPV4_ALT_POOL_ENABLED" = "1" ]; then
    ALT_POOLS="[ { \"pool\": \"${ALT_NET3}.100 - ${ALT_NET3}.200\" } ]"
fi

N1_HEX=$(printf '%02x' "$n1")
N2_HEX=$(printf '%02x' "$n2")
N3_HEX=$(printf '%02x' "$n3")
RFC3442_ROUTES="00:${N1_HEX}:${N2_HEX}:${N3_HEX}:fe:19:c6:33:64:80:${N1_HEX}:${N2_HEX}:${N3_HEX}:fe:18:cb:00:71:${N1_HEX}:${N2_HEX}:${N3_HEX}:fe"
_rfc3442_index=0
while [ "$_rfc3442_index" -lt "$RFC3442_EXTRA_ROUTE_COUNT" ]; do
    RFC3442_INDEX_HEX=$(printf '%02x' "$_rfc3442_index")
    RFC3442_ROUTES="${RFC3442_ROUTES}:18:0a:c8:${RFC3442_INDEX_HEX}:${N1_HEX}:${N2_HEX}:${N3_HEX}:fe"
    _rfc3442_index=$(( _rfc3442_index + 1 ))
done

KEA_VERSION=$(kea-dhcp4 -v 2>/dev/null | head -n 1)
case "$KEA_VERSION" in
    3.*)
        RFC3442_OPTION_DEF_ITEM=""
        ;;
    *)
        RFC3442_OPTION_DEF_ITEM=',
      {
        "name": "classless-static-route",
        "code": 121,
        "type": "binary",
        "space": "dhcp4"
      }'
        ;;
esac

RFC3396_LONG_OPTION=""
_rfc3396_count=0
while [ "$_rfc3396_count" -lt 20 ]; do
    RFC3396_LONG_OPTION="${RFC3396_LONG_OPTION}0123456789abcdef"
    _rfc3396_count=$(( _rfc3396_count + 1 ))
done

PING_CHECK_HOOKS='[]'
if [ "$DHCPV4_PING_CHECK_ENABLED" = "1" ]; then
    PING_CHECK_LIBRARY=$(find /usr/lib /usr/local/lib -name libdhcp_ping_check.so -print -quit 2>/dev/null || true)
    if [ -z "$PING_CHECK_LIBRARY" ]; then
        echo "[kea] ERROR: ping-check requested but libdhcp_ping_check.so is unavailable" >&2
        exit 1
    fi
    PING_CHECK_HOOKS="[
      {
        \"library\": \"$PING_CHECK_LIBRARY\",
        \"parameters\": {
          \"enable-ping-check\": true,
          \"min-ping-requests\": 1,
          \"reply-timeout\": $DHCPV4_PING_TIMEOUT_MS
        }
      }
    ]"
fi

mkdir -p /etc/kea /data /run/kea /var/run/kea /var/lib/kea
# A container may be restarted after SIGKILL with the old PID file still on
# its writable layer. PID 1 is then the entrypoint itself, so Kea otherwise
# mistakes the stale file for a running daemon and refuses crash recovery.
rm -f /run/kea/*.pid /var/run/kea/*.pid

# RFC 4702: dhcp-ddns.enable-updates lets kea-dhcp4 negotiate and echo the
# Client FQDN option (81).  kea-dhcp-ddns (D2) is intentionally not started --
# only the option echo is under test, not the DNS update delivery.
cat > /etc/kea/kea-dhcp4.conf << CONF
{
  "Dhcp4": {
    "authoritative": true,
    "hooks-libraries": $PING_CHECK_HOOKS,
    "interfaces-config": {
      "interfaces": [ "$IFACE" ]
    },
    "dhcp-ddns": {
      "enable-updates": true
    },
    "ddns-send-updates": true,
    "ddns-qualifying-suffix": "dhcp-acceptance.test",
    "option-def": [
      {
        "name": "rfc3396-long-option",
        "code": 224,
        "type": "string",
        "space": "dhcp4"
      }$RFC3442_OPTION_DEF_ITEM
    ],
    "client-classes": [
      {
        "name": "acceptance-class",
        "test": "option[60].text == '$DHCPV4_CLASS_NAME'",
        "option-data": [
          { "name": "domain-name", "data": "class.acceptance.test" }
        ]
      },
      {
        "name": "rfc3396-reassembled-host-name",
        "test": "option[12].text == 'client-fragmented-hostname'",
        "option-data": [
          { "name": "domain-name", "data": "$DHCPV4_RFC3396_POLICY_DOMAIN" }
        ]
      }
    ],
    "lease-database": {
      "type": "memfile",
      "name": "$LEASE_FILE",
      "persist": true
    },
    "renew-timer": 60,
    "rebind-timer": 105,
    "valid-lifetime": 120,
    "subnet4": [
      $OVERLAP_SUBNET_BEFORE
      {
        "id": 1,
        "subnet": "$NET/$PREFIX",
        "reservations-out-of-pool": true,
        "reservations": [
          {
            "hw-address": "$DHCPV4_RESERVED_MAC",
            "ip-address": "${NET3}.${DHCPV4_RESERVED_OFFSET}"
          }
        ],
        "pools": [ { "pool": "${NET3}.${DHCPV4_POOL_START_OFFSET} - ${NET3}.${DHCPV4_POOL_END_OFFSET}" } ],
        "option-data": [
          { "name": "routers", "data": "${NET3}.1" },
          { "name": "subnet-mask", "data": "$NETMASK" },
          { "name": "domain-name-servers", "data": "8.8.8.8, 1.1.1.1" }$PRIMARY_OVERLAP_OPTION,
          {
            "name": "classless-static-route",
            "data": "$RFC3442_ROUTES",
            "csv-format": false
          },
          { "name": "v6-only-preferred", "data": "$RFC8925_WAIT" },
          { "name": "rfc3396-long-option", "data": "$RFC3396_LONG_OPTION" }
        ]
      },
      {
        "id": 2,
        "subnet": "$ALT_SUBNET_CIDR",
        "pools": $ALT_POOLS,
        "option-data": [
          { "name": "routers", "data": "${ALT_ROUTER_IP}" },
          { "name": "subnet-mask", "data": "$NETMASK" },
          { "name": "domain-name-servers", "data": "8.8.8.8" }
        ]
      },
      {
        "id": 3,
        "subnet": "$DHCPV4_RELAY_SUBNET",
        "pools": [ { "pool": "${RELAY_NET3}.100 - ${RELAY_NET3}.120" } ],
        "option-data": [
          { "name": "routers", "data": "${RELAY_NET3}.1" },
          { "name": "domain-name-servers", "data": "8.8.8.8" },
          { "name": "rfc3396-long-option", "data": "$RFC3396_LONG_OPTION" }
        ]
      }$OVERLAP_SUBNET_AFTER
    ],
    "loggers": [
      {
        "name": "kea-dhcp4",
        "output_options": [ { "output": "stdout" } ],
        "severity": "INFO"
      }
    ]
  }
}
CONF

echo "[kea] version=$KEA_VERSION interface=$IFACE ip=$IP netmask=$NETMASK network=$NET pool=${NET3}.${DHCPV4_POOL_START_OFFSET}-${NET3}.${DHCPV4_POOL_END_OFFSET} alt_subnet=$ALT_SUBNET_CIDR overlap_order=$DHCPV4_OVERLAP_ORDER"
echo "[kea] Generated /etc/kea/kea-dhcp4.conf:"
cat /etc/kea/kea-dhcp4.conf

exec kea-dhcp4 -c /etc/kea/kea-dhcp4.conf
