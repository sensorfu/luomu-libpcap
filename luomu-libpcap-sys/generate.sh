#!/bin/sh -e

LIBPCAP='libpcap-1.10.5'

./verify.sh "${LIBPCAP}.tar.xz"

DEST=$(mktemp -d)
mkdir -p "${DEST}"

xz -c "${LIBPCAP}.tar.xz" | tar xf - -C "${DEST}"

bindgen \
    "${DEST}/${LIBPCAP}/pcap/pcap.h" \
    -o src/pcap.rs \
    --allowlist-function='^pcap_.*' \
    --allowlist-type='^pcap_.*' \
    --allowlist-var='^PCAP_.*' \
    --allowlist-var='^DLT_.*' \
    --opaque-type='^timeval' \
    --opaque-type='^sockaddr' \
    --opaque-type='^FILE' \
    -- \
    -I"${DEST}/${LIBPCAP}"

rm -rf "${DEST}"
