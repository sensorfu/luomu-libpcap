#!/bin/sh -e

if [ -z "$1" ]; then
    echo "$0 libpcap-<version>.tar.gz"
    exit 1
fi

gpg --receive-keys E089DEF1D9C15D0D
gpg --verify "$1.sig"
