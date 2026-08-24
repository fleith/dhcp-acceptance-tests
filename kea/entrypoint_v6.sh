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

case "$DHCPV6_RAPID_COMMIT" in
    1) RAPID_COMMIT_JSON=true ;;
    0) RAPID_COMMIT_JSON=false ;;
    *)
        echo "[kea6] ERROR: DHCPV6_RAPID_COMMIT must be 0 or 1" >&2
        exit 1
        ;;
esac

PREFERENCE_OPTION=""
if [ -n "$DHCPV6_PREFERENCE" ]; then
    PREFERENCE_OPTION=',
          { "name": "preference", "data": "'"$DHCPV6_PREFERENCE"'" }'
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
    "dhcp-ddns": {
      "enable-updates": true
    },
    "ddns-send-updates": true,
    "ddns-qualifying-suffix": "dhcp-acceptance.test",
    "lease-database": {
      "type": "memfile",
      "name": "/var/lib/kea/kea-leases6.csv",
      "persist": true
    },
    "renew-timer": 60,
    "rebind-timer": 105,
    "preferred-lifetime": 120,
    "valid-lifetime": 120,
    "subnet6": [
      {
        "id": 1,
        "subnet": "$DHCPV6_SUBNET",
        "interface": "$IFACE",
        "rapid-commit": $RAPID_COMMIT_JSON,
        "pools": [ { "pool": "$DHCPV6_POOL" } ],
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
        "output_options": [ { "output": "stdout" } ],
        "severity": "INFO"
      }
    ]
  }
}
CONF

echo "[kea6] interface=$IFACE subnet=$DHCPV6_SUBNET pool=$DHCPV6_POOL pd=$DHCPV6_PD_PREFIX/$DHCPV6_PD_PREFIX_LEN->$DHCPV6_PD_DELEGATED_LEN link_local=$KEA_LL"
echo "[kea6] Generated /etc/kea/kea-dhcp6.conf:"
cat /etc/kea/kea-dhcp6.conf

echo "[kea6] Interface addresses:"
ip -6 addr show dev "$IFACE"

exec kea-dhcp6 -c /etc/kea/kea-dhcp6.conf
