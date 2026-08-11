ARG ISC_DHCP_BASE_IMAGE=networkboot/dhcpd:1.3.0
FROM ${ISC_DHCP_BASE_IMAGE}
RUN DEBIAN_FRONTEND=noninteractive apt-get update -qq \
    && apt-get install -y --no-install-recommends isc-dhcp-server iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
COPY entrypoint_v6.sh /entrypoint_v6.sh
RUN chmod +x /entrypoint.sh /entrypoint_v6.sh
ENTRYPOINT ["/entrypoint.sh"]
