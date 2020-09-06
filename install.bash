#!/bin/bash

set -eu

. /etc/os-release

STAGE=${STAGE:-stable}

function error_not_supported {
	echo "Sorry, $ID $VERSION_ID is not yet supported by the quickstart install script."
	exit 1
}

case $ID in
	ubuntu)
		export DEBIAN_FRONTEND=non-interactive
		echo "deb https://dl.bintray.com/wiregarden-io/${STAGE} ${VERSION_CODENAME} main" > /etc/apt/sources.list.d/wiregarden.list
		sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-key 379CE192D401AB61
		case $VERSION_ID in
			20.04)
				sudo apt-get update
				sudo apt-get install -y wiregarden wireguard-tools libnss-wiregarden
				;;
			16.04|18.04)
				sudo apt-get update
				sudo apt-get install -y software-properties-common
				sudo add-apt-repository -y ppa:wireguard/wireguard
				sudo apt-get update
				sudo apt-get install -y wiregarden wireguard wireguard-tools libnss-wiregarden
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

