FROM debian:bookworm-slim
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends kea-dhcp4-server iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
