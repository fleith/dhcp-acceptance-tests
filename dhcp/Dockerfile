FROM networkboot/dhcpd:latest
RUN apt-get update -qq && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
