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

if [ "$EUID" -eq 0 ]; then
	echo "Please run as current user"
	exit
fi

function do_clone {
	echo -n "Cloning $1..."
	git clone $1 &>/dev/null
	die "$?" "Could not clone the repository '$1'. Check the internet!"
	printf "${GREEN}done!${NC}\n"
}

function do_make {
	echo -n "Making $1..."
	make -j8 &>/dev/null
	die "$?" "There was an error with make $1. EXITING!" "make"
	printf "${GREEN}done!${NC}\n"
}

function do_install {
	echo -n "Installing $1..."
	# sudo make install >/dev/null
	die "$?" "There was an error installing $1. EXITING!"
	printf "${GREEN}done!${NC}\n"
}

function do_configure {
	echo -n "Configuring $1..."
	./configure > /dev/null
	die "$?" "There was an error with configuring $TOOL. EXITING!"
	printf "${GREEN}done!${NC}\n"
}

sudo ls >/dev/null
die "$?" "Sudo password not introduced. Exiting!"

mkdir sources 2>/dev/null
cd sources


# Install hcxtools
TOOL="hcxtools"
sudo apt-get install -y libcurl4-openssl-dev libssl-dev zlib1g-dev libpcap-dev >/dev/null

do_clone "https://github.com/ZerBea/hcxtools.git"
cd "$TOOL"
do_make "$TOOL"
do_install "$TOOL"

printf "${GREEN}$TOOL successfully installed!${NC}\n"
cd ..



# Install hashcat
TOOL="hashcat"

do_clone "https://github.com/hashcat/hashcat.git"
cd "$TOOL"

# This is needed because the new hashcat is incompatible with the cracker
git checkout c0a31b3239a3099979b7d96ce38e63a59fc26990 &>/dev/null
die "$?" "Error checking out correct $TOOL branch. EXITING!"

do_make "$TOOL"
do_install "$TOOL"

printf "${GREEN}$TOOL successfully installed!${NC}\n"
cd ..



# install john
TOOL="john"
sudo apt-get install -y libcurl4-openssl-dev libssl-dev zlib1g-dev libpcap-dev build-essential libssl-dev zlib1g-dev yasm libgmp-dev libpcap-dev pkg-config libbz2-dev nvidia-opencl-dev ocl-icd-opencl-dev opencl-headers pocl-opencl-icd >/dev/null

do_clone "git://github.com/magnumripper/JohnTheRipper -b bleeding-jumbo $TOOL"

cd "$TOOL/src"

do_configure "$TOOL"
do_make "$TOOL"
do_install "$TOOL"

printf "${GREEN}$TOOL successfully installed!${NC}\n"
cd ../..
