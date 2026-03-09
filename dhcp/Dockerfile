FROM networkboot/dhcpd:latest
RUN apt-get update -qq && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
COPY entrypoint_v6.sh /entrypoint_v6.sh
RUN chmod +x /entrypoint.sh /entrypoint_v6.sh
ENTRYPOINT ["/entrypoint.sh"]
