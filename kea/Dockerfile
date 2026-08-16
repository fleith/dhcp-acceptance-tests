ARG KEA_BASE_IMAGE=debian:bookworm-slim
FROM ${KEA_BASE_IMAGE}
USER root
ARG KEA_INSTALL_MODE=debian
RUN set -eux; \
    case "$KEA_INSTALL_MODE" in \
        debian) \
            apt-get update -qq; \
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                kea-dhcp4-server kea-dhcp6-server iproute2 e2fsprogs; \
            rm -rf /var/lib/apt/lists/*; \
            ;; \
        alpine) \
            apk add --no-cache iproute2 util-linux e2fsprogs; \
            ;; \
        *) \
            echo "Unsupported KEA_INSTALL_MODE=$KEA_INSTALL_MODE" >&2; \
            exit 2; \
            ;; \
    esac
COPY entrypoint.sh /entrypoint.sh
COPY entrypoint_v6.sh /entrypoint_v6.sh
COPY storage_fault_entrypoint.sh /storage-fault-entrypoint.sh
RUN chmod +x /entrypoint.sh /entrypoint_v6.sh /storage-fault-entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
