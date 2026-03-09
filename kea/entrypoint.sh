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

mkdir -p /etc/kea /data /run/kea /var/run/kea /var/lib/kea
cat > /etc/kea/kea-dhcp4.conf << CONF
{
  "Dhcp4": {
    "authoritative": true,
    "interfaces-config": {
      "interfaces": [ "$IFACE" ]
    },
    "lease-database": {
      "type": "memfile",
      "name": "/data/kea-leases4.csv",
      "persist": true
    },
    "renew-timer": 60,
    "rebind-timer": 105,
    "valid-lifetime": 120,
    "subnet4": [
      {
        "subnet": "$NET/$PREFIX",
        "pools": [ { "pool": "${NET3}.100 - ${NET3}.200" } ],
        "option-data": [
          { "name": "routers", "data": "${NET3}.1" },
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

echo "[kea] interface=$IFACE ip=$IP netmask=$NETMASK network=$NET"
echo "[kea] Generated /etc/kea/kea-dhcp4.conf:"
cat /etc/kea/kea-dhcp4.conf

exec kea-dhcp4 -c /etc/kea/kea-dhcp4.conf