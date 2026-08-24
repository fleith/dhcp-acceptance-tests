#!/bin/sh
# Start Kea DHCP-DDNS with one forward RFC 2136 domain for the isolated tests.

set -e

DDNS_LISTEN_IP="${DHCPV6_DDNS_LISTEN_IP:-0.0.0.0}"
DDNS_LISTEN_PORT="${DHCPV6_DDNS_MANAGER_PORT:-53001}"
DDNS_SERVER_IP="${DHCPV6_DDNS_SERVER_IP:-172.29.0.4}"
DDNS_SERVER_PORT="${DHCPV6_DDNS_SERVER_PORT:-53}"
DDNS_ZONE="${DHCPV6_DDNS_SUFFIX:-dhcp-acceptance.test}"

mkdir -p /etc/kea /run/kea /var/run/kea
cat > /etc/kea/kea-dhcp-ddns.conf << CONF
{
  "DhcpDdns": {
    "ip-address": "$DDNS_LISTEN_IP",
    "port": $DDNS_LISTEN_PORT,
    "dns-server-timeout": 100,
    "ncr-protocol": "UDP",
    "ncr-format": "JSON",
    "forward-ddns": {
      "ddns-domains": [
        {
          "name": "$DDNS_ZONE.",
          "dns-servers": [
            {
              "ip-address": "$DDNS_SERVER_IP",
              "port": $DDNS_SERVER_PORT
            }
          ]
        }
      ]
    },
    "reverse-ddns": {
      "ddns-domains": []
    },
    "loggers": [
      {
        "name": "kea-dhcp-ddns",
        "output_options": [ { "output": "stdout" } ],
        "severity": "INFO"
      }
    ]
  }
}
CONF

echo "[kea-d2] listen=$DDNS_LISTEN_IP:$DDNS_LISTEN_PORT zone=$DDNS_ZONE server=$DDNS_SERVER_IP:$DDNS_SERVER_PORT"
echo "[kea-d2] Generated /etc/kea/kea-dhcp-ddns.conf:"
cat /etc/kea/kea-dhcp-ddns.conf

exec kea-dhcp-ddns -c /etc/kea/kea-dhcp-ddns.conf
