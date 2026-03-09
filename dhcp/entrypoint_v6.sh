#!/bin/sh
set -e

IFACE="${1:-eth0}"
DHCPV6_SUBNET="${DHCPV6_SUBNET:-fd00:29::/64}"
DHCPV6_RANGE_START="${DHCPV6_RANGE_START:-fd00:29::100}"
DHCPV6_RANGE_END="${DHCPV6_RANGE_END:-fd00:29::1ff}"
DHCPV6_DNS="${DHCPV6_DNS:-2001:4860:4860::8888}"
DHCPV6_DOMAIN_SEARCH="${DHCPV6_DOMAIN_SEARCH:-example.test}"

if ! ip -6 addr show "$IFACE" | grep -q "scope global"; then
    echo "[dhcpd6] ERROR: No global IPv6 address on $IFACE" >&2
    exit 1
fi

mkdir -p /data
cat > /data/dhcpd6.conf << CONF
default-lease-time 120;
preferred-lifetime 120;
option dhcp-renewal-time 60;
option dhcp-rebinding-time 105;

subnet6 $DHCPV6_SUBNET {
    range6 $DHCPV6_RANGE_START $DHCPV6_RANGE_END;
    option dhcp6.name-servers $DHCPV6_DNS;
    option dhcp6.domain-search "$DHCPV6_DOMAIN_SEARCH";
}
CONF

touch /data/dhcpd6.leases

echo "[dhcpd6] interface=$IFACE subnet=$DHCPV6_SUBNET range=$DHCPV6_RANGE_START-$DHCPV6_RANGE_END"
echo "[dhcpd6] Generated /data/dhcpd6.conf:"
cat /data/dhcpd6.conf

exec dhcpd -6 -f -cf /data/dhcpd6.conf -lf /data/dhcpd6.leases "$IFACE"
