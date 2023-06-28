#!/bin/sh -e

LIBPCAP='libpcap-1.10.4'

./verify.sh "${LIBPCAP}.tar.gz"

DEST=$(mktemp -d)
mkdir -p "${DEST}"

gunzip -c "${LIBPCAP}.tar.gz" | tar xf - -C "${DEST}"

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
