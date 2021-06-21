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
    --whitelist-function='^pcap_.*' \
    --whitelist-type='^pcap_.*' \
    --whitelist-var='^PCAP_.*' \
    --blacklist-type='^__.*' \
    --blacklist-type='^sa_.*' \
    --blacklist-type='^sockaddr' \
    --blacklist-type='^size_t' \
    --blacklist-type='^timeval' \
    --blacklist-type='FILE' \
    --blacklist-type='fpos_t' \
    --blacklist-type='size_t' \
    --blacklist-type='u_.*' \
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
