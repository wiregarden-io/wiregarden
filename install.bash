#!/bin/bash

set -eu

. /etc/os-release

function error_not_supported {
	echo "Sorry, $ID $VERSION_ID is not yet supported by the quickstart install script."
	exit 1
}

case $ID in
	ubuntu)
		export DEBIAN_FRONTEND=non-interactive
		case $VERSION_ID in
			20.04)
				sudo apt-get update
				sudo apt-get install -y wireguard wireguard-tools
				;;
			16.04|18.04)
				sudo add-apt-repository -y ppa:wireguard/wireguard
				sudo apt-get update
				sudo apt-get install -y wireguard wireguard-tools
				;;
			*)
				error_not_supported
				;;
		esac
		;;
	*)
		error_not_supported
		;;
esac

sudo wget -O /usr/local/bin/wiregarden https://wiregarden.io/dist/latest/wiregarden
chmod +x /usr/local/bin/wiregarden

