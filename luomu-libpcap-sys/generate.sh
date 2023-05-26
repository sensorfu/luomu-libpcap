#!/bin/sh -e

LIBPCAP='libpcap-1.10.1'

./verify.sh "${LIBPCAP}.tar.gz"

DEST=$(mktemp -d)
mkdir -p "${DEST}"

gunzip -c "${LIBPCAP}.tar.gz" | tar xf - -C "${DEST}"

bindgen \
    "${DEST}/${LIBPCAP}/pcap/pcap.h" \
    --distrust-clang-mangling \
    --use-core \
    --ctypes-prefix='libc' \
    --allowlist-function='^pcap_.*' \
    --allowlist-type='^pcap_.*' \
    --allowlist-var='^PCAP_.*' \
    --blocklist-type='^__.*' \
    --blocklist-type='^sa_.*' \
    --blocklist-type='^sockaddr' \
    --blocklist-type='^size_t' \
    --blocklist-type='^timeval' \
    --blocklist-type='FILE' \
    --blocklist-type='fpos_t' \
    --blocklist-type='size_t' \
    --blocklist-type='u_.*' \
    -o src/pcap.rs \
    -- \
    -I"${DEST}/${LIBPCAP}"

bindgen \
    "${DEST}/${LIBPCAP}/pcap/dlt.h" \
    --distrust-clang-mangling \
    --use-core \
    -o src/dlt.rs \
    -- \
    -I"${DEST}/${LIBPCAP}"

rm -rf "${DEST}"
