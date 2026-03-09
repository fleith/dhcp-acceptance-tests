#!/bin/sh
set -e

IFACE="${1:-eth0}"
DHCPV6_SUBNET="${DHCPV6_SUBNET:-fd00:29::/64}"
DHCPV6_POOL="${DHCPV6_POOL:-fd00:29::100 - fd00:29::1ff}"
DHCPV6_DNS="${DHCPV6_DNS:-2001:4860:4860::8888}"

if ! ip -6 addr show "$IFACE" | grep -q "scope global"; then
    echo "[kea6] ERROR: No global IPv6 address on $IFACE" >&2
    exit 1
fi

# Kea derives a link-local from the interface MAC and binds UDP/547 to it.
# Docker interfaces may use a non-EUI64 link-local, so add the expected EUI64
# address explicitly to avoid startup bind failures.
MAC=$(cat "/sys/class/net/$IFACE/address")
IFS=: read -r m1 m2 m3 m4 m5 m6 << EOF
$MAC
EOF
m1_flipped=$(printf "%02x" $(( 0x$m1 ^ 0x02 )))
KEA_LL="fe80::${m1_flipped}${m2}:${m3}ff:fe${m4}:${m5}${m6}"
ip -6 addr add "${KEA_LL}/64" dev "$IFACE" nodad >/dev/null 2>&1 || true
for i in $(seq 1 20); do
    if ip -6 addr show dev "$IFACE" | grep -q "$KEA_LL"; then
        break
    fi
    sleep 0.2
done

mkdir -p /etc/kea /data /run/kea /var/run/kea /var/lib/kea
cat > /etc/kea/kea-dhcp6.conf << CONF
{
  "Dhcp6": {
    "interfaces-config": {
      "interfaces": [ "$IFACE" ]
    },
    "lease-database": {
      "type": "memfile",
      "name": "/data/kea-leases6.csv",
      "persist": true
    },
    "renew-timer": 60,
    "rebind-timer": 105,
    "preferred-lifetime": 120,
    "valid-lifetime": 120,
    "subnet6": [
      {
        "subnet": "$DHCPV6_SUBNET",
        "pools": [ { "pool": "$DHCPV6_POOL" } ],
        "option-data": [
          { "name": "dns-servers", "data": "$DHCPV6_DNS" }
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

echo "[kea6] interface=$IFACE subnet=$DHCPV6_SUBNET pool=$DHCPV6_POOL link_local=$KEA_LL"
echo "[kea6] Generated /etc/kea/kea-dhcp6.conf:"
cat /etc/kea/kea-dhcp6.conf

echo "[kea6] Interface addresses:"
ip -6 addr show dev "$IFACE"

exec kea-dhcp6 -c /etc/kea/kea-dhcp6.conf