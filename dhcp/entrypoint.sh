#!/bin/sh
set -e

IFACE="${1:-eth0}"

# Detect IP and prefix length from the interface
IP_PREFIX=$(ip -4 addr show "$IFACE" | awk '/inet / {print $2; exit}')
if [ -z "$IP_PREFIX" ]; then
    echo "[dhcpd] ERROR: No IPv4 address on $IFACE" >&2
    exit 1
fi

IP="${IP_PREFIX%%/*}"
PREFIX="${IP_PREFIX##*/}"
ALT_SUBNET_CIDR="${RFC3011_ALT_SUBNET:-}"
ALT_SERVER_IP="${RFC3011_ALT_SERVER_IP:-}"
RFC8925_WAIT="${RFC8925_WAIT:-1800}"
DHCPV4_POOL_START_OFFSET="${DHCPV4_POOL_START_OFFSET:-100}"
DHCPV4_POOL_END_OFFSET="${DHCPV4_POOL_END_OFFSET:-200}"
DHCPV4_ALT_POOL_ENABLED="${DHCPV4_ALT_POOL_ENABLED:-1}"
DHCPV4_RESERVED_MAC="${DHCPV4_RESERVED_MAC:-02:00:00:ff:00:01}"
DHCPV4_RESERVED_OFFSET="${DHCPV4_RESERVED_OFFSET:-50}"
DHCPV4_CLASS_NAME="${DHCPV4_CLASS_NAME:-acceptance-class}"
DHCPV4_RELAY_SUBNET="${DHCPV4_RELAY_SUBNET:-172.29.2.0/24}"
DHCPV4_INJECT_OVERLAPPING_SUBNET="${DHCPV4_INJECT_OVERLAPPING_SUBNET:-0}"
DHCPV4_FORCE_STORAGE_FAILURE="${DHCPV4_FORCE_STORAGE_FAILURE:-0}"

# Convert prefix length to dotted-decimal netmask
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

# Compute network address (bitwise AND of IP and netmask octets)
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
ALT_PREFIX="${ALT_SUBNET_CIDR##*/}"
ALT_NET3="$(echo "$ALT_NET" | cut -d. -f1-3)"
if [ -z "$ALT_SERVER_IP" ]; then
    ALT_SERVER_IP="${ALT_NET3}.2"
fi
ALT_ROUTER_IP="${ALT_NET3}.1"
RELAY_NET="${DHCPV4_RELAY_SUBNET%%/*}"
RELAY_PREFIX="${DHCPV4_RELAY_SUBNET##*/}"
RELAY_NET3="$(echo "$RELAY_NET" | cut -d. -f1-3)"

# The relay subnet is remote: install only a route so replies to giaddr leave
# through the Docker test interface without making it a directly served link.
ip route add "$DHCPV4_RELAY_SUBNET" dev "$IFACE" >/dev/null 2>&1 || true

OVERLAP_SUBNET_DECL=""
if [ "$DHCPV4_INJECT_OVERLAPPING_SUBNET" = "1" ]; then
    OVERLAP_SUBNET_DECL="subnet $NET netmask 255.255.255.128 { range ${NET3}.10 ${NET3}.20; }"
fi

LEASE_FILE=/data/dhcpd.leases
if [ "$DHCPV4_FORCE_STORAGE_FAILURE" = "1" ]; then
    LEASE_FILE=/proc/dhcpd-acceptance-leases
fi

ALT_POOL_RANGE=""
if [ "$DHCPV4_ALT_POOL_ENABLED" = "1" ]; then
    ALT_POOL_RANGE="range ${ALT_NET3}.100 ${ALT_NET3}.200;"
fi

# Give dhcpd a local address on the alternate subnet so it can serve that pool
# and emit a valid server identifier for RFC 3011 selection tests.
ip addr add "${ALT_SERVER_IP}/${ALT_PREFIX}" dev "$IFACE" >/dev/null 2>&1 || true

mkdir -p /data
cat > /data/dhcpd.conf << CONF
# authoritative: send DHCPNAK for addresses this server cannot satisfy
# (RFC 2131 §4.3.2).  Without this, ISC dhcpd stays silent instead of NAKing.
authoritative;

default-lease-time 120;
# min = max = default so dhcpd always grants exactly 120 s regardless of
# whether the client has an existing lease (avoids variable lease_time in
# DHCPACK that would break T1/T2 percentage checks).
min-lease-time 120;
max-lease-time 120;
# RFC 2131 §4.4.5: T1 = 50% of lease time, T2 = 87.5%
option dhcp-renewal-time 60;
option dhcp-rebinding-time 105;

# RFC 3442 and RFC 8925 options are scoped to the primary test subnet below.
option classless-static-routes code 121 = array of unsigned integer 8;
option v6-only-preferred code 108 = unsigned integer 32;

class "acceptance-class" {
    match if option vendor-class-identifier = "$DHCPV4_CLASS_NAME";
    option domain-name "class.acceptance.test";
}

host acceptance-reserved {
    hardware ethernet $DHCPV4_RESERVED_MAC;
    fixed-address ${NET3}.${DHCPV4_RESERVED_OFFSET};
}

# RFC 4702: enable DDNS so dhcpd negotiates the Client FQDN option (81) and
# echoes it back in the OFFER/ACK.  The .test TLD (RFC 6761) keeps any actual
# DNS update attempt local and fast-failing; the acceptance test only exercises
# the option echo, not the DNS update itself.
ddns-update-style interim;
ddns-updates on;
ddns-domainname "dhcp-acceptance.test";
ddns-rev-domainname "in-addr.arpa";

shared-network dhcp-test-shared {
subnet $NET netmask $NETMASK {
    # Always send broadcast responses so the test-runner's sniffer captures
    # unicast-destined replies even when the client IP is not configured locally.
    always-broadcast on;
    range ${NET3}.${DHCPV4_POOL_START_OFFSET} ${NET3}.${DHCPV4_POOL_END_OFFSET};
    option routers ${NET3}.1;
    option subnet-mask $NETMASK;
    option domain-name-servers 8.8.8.8;
    option classless-static-routes
        0, $n1, $n2, $n3, 254,
        25, 198, 51, 100, 128, $n1, $n2, $n3, 254,
        24, 203, 0, 113, $n1, $n2, $n3, 254;
    option v6-only-preferred $RFC8925_WAIT;
}
subnet $ALT_NET netmask $NETMASK {
    always-broadcast on;
    $ALT_POOL_RANGE
    option routers ${ALT_ROUTER_IP};
    option subnet-mask $NETMASK;
    option domain-name-servers 8.8.8.8;
}
}

subnet $RELAY_NET netmask $(prefix_to_netmask "$RELAY_PREFIX") {
    range ${RELAY_NET3}.100 ${RELAY_NET3}.120;
    option routers ${RELAY_NET3}.1;
    option subnet-mask $(prefix_to_netmask "$RELAY_PREFIX");
    option domain-name-servers 8.8.8.8;
}
$OVERLAP_SUBNET_DECL
CONF

touch "$LEASE_FILE"

echo "[dhcpd] interface=$IFACE ip=$IP netmask=$NETMASK network=$NET pool=${NET3}.${DHCPV4_POOL_START_OFFSET}-${NET3}.${DHCPV4_POOL_END_OFFSET} alt_subnet=$ALT_SUBNET_CIDR alt_server_ip=$ALT_SERVER_IP"
echo "[dhcpd] Generated /data/dhcpd.conf:"
cat /data/dhcpd.conf

exec dhcpd -f -cf /data/dhcpd.conf -lf "$LEASE_FILE" "$IFACE"
