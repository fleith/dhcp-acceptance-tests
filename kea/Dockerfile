FROM debian:bookworm-slim
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends kea-dhcp4-server kea-dhcp6-server iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
COPY entrypoint_v6.sh /entrypoint_v6.sh
RUN chmod +x /entrypoint.sh /entrypoint_v6.sh
ENTRYPOINT ["/entrypoint.sh"]
