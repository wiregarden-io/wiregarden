#!/bin/bash

set -eu

if [ "$(id -u)" != "0" ]; then
	echo "This script must be run as root."
	exit 1
fi

if [ "$(uname -m)" != "x86_64" ]; then
	echo "Sorry, your architecture is not yet supported."
	echo "Please contact@wiregarden.io for assistance."
	exit 1
fi

which wget || (
	echo "wget not found, please install and try again"
	exit 1
)

BIN_URL="https://github.com/wiregarden-io/wiregarden/releases/latest/download/wiregarden_linux_amd64"
SUMS_URL="https://github.com/wiregarden-io/wiregarden/releases/latest/download/SHA256SUMS"

tmpbin=$(mktemp)
tmpsums=$(mktemp)
trap "rm -rf $tmpbin $tmpsums" EXIT
wget -O $tmpbin $BIN_URL
wget -O $tmpsums $SUMS_URL

verify_sha256=$(awk '{print $1}' $tmpsums)
actual_sha256=$(sha256sum $tmpbin | awk '{print $1}')
if [ "$verify_sha256" != "$actual_sha256" ]; then
	echo "Binary does not match expected sha256. Please try again?"
	exit 1
fi

systemctl stop wiregarden || true
cp $tmpbin /usr/local/bin/wiregarden
chmod +x /usr/local/bin/wiregarden
/usr/local/bin/wiregarden setup
echo "Wiregarden installation complete. See https://wiregarden.io/networks for next steps."

