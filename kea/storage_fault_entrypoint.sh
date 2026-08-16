#!/bin/sh
set -eu

TARGET="${DHCPV4_STORAGE_TARGET:?DHCPV4_STORAGE_TARGET is required}"
IMAGE=/storage-fault-backing/lease-store.ext4

mkdir -p /storage-fault-backing "$TARGET"
if [ ! -s "$IMAGE" ]; then
    truncate -s 32M "$IMAGE"
    mkfs.ext4 -q -F "$IMAGE"
fi
mount -o loop,rw "$IMAGE" "$TARGET"

exec /entrypoint.sh "$@"
