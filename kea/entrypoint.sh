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
DHCPV4_POOL_START_OFFSET="${DHCPV4_POOL_START_OFFSET:-100}"
DHCPV4_POOL_END_OFFSET="${DHCPV4_POOL_END_OFFSET:-200}"
DHCPV4_ALT_POOL_ENABLED="${DHCPV4_ALT_POOL_ENABLED:-1}"

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

ALT_POOLS='[]'
if [ "$DHCPV4_ALT_POOL_ENABLED" = "1" ]; then
    ALT_POOLS="[ { \"pool\": \"${ALT_NET3}.100 - ${ALT_NET3}.200\" } ]"
fi

N1_HEX=$(printf '%02x' "$n1")
N2_HEX=$(printf '%02x' "$n2")
N3_HEX=$(printf '%02x' "$n3")
RFC3442_ROUTES="00:${N1_HEX}:${N2_HEX}:${N3_HEX}:fe:19:c6:33:64:80:${N1_HEX}:${N2_HEX}:${N3_HEX}:fe:18:cb:00:71:${N1_HEX}:${N2_HEX}:${N3_HEX}:fe"

KEA_VERSION=$(kea-dhcp4 -v 2>/dev/null | head -n 1)
case "$KEA_VERSION" in
    3.*)
        RFC3442_OPTION_DEF=""
        ;;
    *)
        RFC3442_OPTION_DEF='    "option-def": [
      {
        "name": "classless-static-route",
        "code": 121,
        "type": "binary",
        "space": "dhcp4"
      }
    ],'
        ;;
esac

mkdir -p /etc/kea /data /run/kea /var/run/kea /var/lib/kea

# RFC 4702: dhcp-ddns.enable-updates lets kea-dhcp4 negotiate and echo the
# Client FQDN option (81).  kea-dhcp-ddns (D2) is intentionally not started --
# only the option echo is under test, not the DNS update delivery.
cat > /etc/kea/kea-dhcp4.conf << CONF
{
  "Dhcp4": {
    "authoritative": true,
    "interfaces-config": {
      "interfaces": [ "$IFACE" ]
    },
    "dhcp-ddns": {
      "enable-updates": true
    },
    "ddns-send-updates": true,
    "ddns-qualifying-suffix": "dhcp-acceptance.test",
$RFC3442_OPTION_DEF
    "lease-database": {
      "type": "memfile",
      "name": "/var/lib/kea/kea-leases4.csv",
      "persist": true
    },
    "renew-timer": 60,
    "rebind-timer": 105,
    "valid-lifetime": 120,
    "subnet4": [
      {
        "id": 1,
        "subnet": "$NET/$PREFIX",
        "pools": [ { "pool": "${NET3}.${DHCPV4_POOL_START_OFFSET} - ${NET3}.${DHCPV4_POOL_END_OFFSET}" } ],
        "option-data": [
          { "name": "routers", "data": "${NET3}.1" },
          { "name": "subnet-mask", "data": "$NETMASK" },
          { "name": "domain-name-servers", "data": "8.8.8.8" },
          {
            "name": "classless-static-route",
            "data": "$RFC3442_ROUTES",
            "csv-format": false
          },
          { "name": "v6-only-preferred", "data": "$RFC8925_WAIT" }
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
      }
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

echo "[kea] version=$KEA_VERSION interface=$IFACE ip=$IP netmask=$NETMASK network=$NET pool=${NET3}.${DHCPV4_POOL_START_OFFSET}-${NET3}.${DHCPV4_POOL_END_OFFSET} alt_subnet=$ALT_SUBNET_CIDR"
echo "[kea] Generated /etc/kea/kea-dhcp4.conf:"
cat /etc/kea/kea-dhcp4.conf

exec kea-dhcp4 -c /etc/kea/kea-dhcp4.conf
