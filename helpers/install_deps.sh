#!/bin/bash


RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

function die {
if [ "$1" -ne 0 ]; then
	printf "${RED}$2${NC}\n"
	$3
	exit 1
fi
}

function dl_install {
	echo "Installing $TOOL..."

	if [ -z "$FOLD" ]; then
		FOLD=$TOOL
	fi

	if [ -n "$DEPENDENCIES" ]; then
		echo -n "Installing $TOOL dependencies..."
		sudo apt-get install -y $DEPENDENCIES >/dev/null
		echo "done!"
	fi

	if [ -n "$PY_DEPENDENCIES" ]; then
		echo -n "Installing $TOOL python dependencies..."
		sudo pip install $PY_DEPENDENCIES &>/dev/null
		die "$?" "There was an error installing the python dependecies: $PY_DEPENDENCIES"
		echo "done!"
	fi
	
	if [ ! -d "$FOLD" ]; then
	    echo -n "Downloading $TOOL... "
		git clone $LINK &>/dev/null
		die "$?" "Could not clone the repository $LINK. Check the internet!"
		echo "done!"
	else
		echo "Repository already downloaded!"
	fi

	cd $FOLD

	if [ "$PY_INSTALL" == "yes" ]; then
		echo -n "Installing $TOOL... "
		sudo python setup.py install >/dev/null
		echo "done!"
	else
		echo "Building $TOOL"
		if [ $AUTOGEN == "yes" ]; then
			echo -n "Autogenning $TOOL... "
			./autogen.sh  > /dev/null
			die "$?" "There was an error with autogen $TOOL. EXITING!"
			echo "done!"
		fi

		if [ $CONFIGURE == "yes" ]; then
			echo -n "Configuring $TOOL... "
			if [ -z "$CONFIGURE_CMD" ]; then
				./configure > /dev/null
				die "$?" "There was an error with configure $TOOL. EXITING!"
			else
				$CONFIGURE_CMD >/dev/null
				die "$?" "There was an error with configure $TOOL. The command $CONFIGURE_CMD failed! EXITING!"
			fi
			echo "done!"
		fi

		make clean &>/dev/null
		
		echo -n "Making $TOOL... "
		make -j8 &>/dev/null
		die "$?" "There was an error with make $TOOL. EXITING!" "make"
		echo "done!"

		echo -n "Installing $TOOL... "
		if [ -z "$INSTALL_RULE" ]; then
			sudo make install >/dev/null
			die "$?" "There was an error installing $TOOL. EXITING!"
		else
			sudo make "$INSTALL_RULE" >/dev/null
			die "$?" "There was an error installing $TOOL. EXITING!"
		fi
		echo "done!"
	fi

	printf "${GREEN}$TOOL successfully installed!${NC}\n"
}

function simple_install {
	echo -n "Installing $TOOL... "
	sudo apt-get install -y $TOOL
	die "$?" "There was an error installing $TOOL. EXITING!"
	echo "done!"
	printf "${GREEN}$TOOL successfully installed!${NC}\n"
}

function install_aircrack {
	(
		TOOL="aircrack-ng"
		AUTOGEN="yes"
		CONFIGURE="yes"
		LINK="https://github.com/aircrack-ng/aircrack-ng.git"
		DEPENDENCIES="build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre3-dev libhwloc-dev libcmocka-dev"
		INSTALL_RULE="install-strip"
		dl_install
	)
}

function install_hcxtools {
	(
		TOOL="hcxtools"
		AUTOGEN="no"
		CONFIGURE="no"
		LINK="https://github.com/ZerBea/hcxtools.git"
		DEPENDENCIES="libcurl4-openssl-dev libssl-dev zlib1g-dev libpcap-dev"
		dl_install
	)
}

function install_hcxdumptool {
	(
		TOOL="hcxdumptool"
		AUTOGEN="no"
		CONFIGURE="no"
		LINK="https://github.com/ZerBea/hcxdumptool"
		DEPENDENCIES=""
		dl_install
	)
}

function install_hashcat {
	(
		TOOL="hashcat"
		AUTOGEN="no"
		CONFIGURE="no"
		LINK="https://github.com/hashcat/hashcat.git"
		DEPENDENCIES=""
		dl_install
	)
}

function install_reaver {
	(
		TOOL="reaver"
		FOLD="reaver-wps-fork-t6x/src"
		AUTOGEN="no"
		CONFIGURE="yes"
		LINK="https://github.com/t6x/reaver-wps-fork-t6x"
		DEPENDENCIES="build-essential libpcap-dev pixiewps"
		dl_install
	)
}

function install_bully {
	(
		TOOL="bully"
		FOLD="bully/src"
		AUTOGEN="no"
		CONFIGURE="no"
		LINK="https://github.com/aanarchyy/bully.git"
		DEPENDENCIES="build-essential libpcap-dev pixiewps"
		dl_install
	)
}

function install_pyrit {
	(
		TOOL="pyrit"
		FOLD="Pyrit"
		AUTOGEN="no"
		CONFIGURE="no"
		LINK="https://github.com/JPaulMora/Pyrit.git"
		DEPENDENCIES="python-dev libssl-dev zlib1g-dev"
		PY_DEPENDENCIES="psycopg2 scapy"
		PY_INSTALL="yes"
		dl_install
	)
}

function install_tshark {
	(
		TOOL=tshark
		simple_install
	)
}

function install_macchanger {
	(
		TOOL=macchanger
		simple_install
	)
}

function install_john {
	(
		TOOL="john"
		FOLD="john/src"
		AUTOGEN="no"
		CONFIGURE="yes"
		LINK="git://github.com/magnumripper/JohnTheRipper -b bleeding-jumbo john"
		DEPENDENCIES="build-essential libssl-dev zlib1g-dev yasm libgmp-dev libpcap-dev pkg-config libbz2-dev nvidia-opencl-dev ocl-icd-opencl-dev opencl-headers pocl-opencl-icd"
		dl_install
	)
}


if [ "$EUID" -eq 0 ]; then
	echo "Please run as current user"
	exit
fi

sudo ls >/dev/null
die "$?" "Sudo password not introduced. Exiting!"

mkdir sources 2>/dev/null
cd sources

install_aircrack
install_hcxtools
install_hcxdumptool
install_hashcat
install_reaver
install_bully
install_pyrit
install_tshark
install_macchanger
install_john