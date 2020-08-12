#!/bin/sh -e

if [ -z "$1" ]; then
    echo "$0 libpcap-<version>.tar.gz"
    exit 1
fi

gpg --import signing-key.asc
gpg --verify "$1.sig"
