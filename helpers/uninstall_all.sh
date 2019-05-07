#!/bin/bash

function die {
if [ "$1" -ne 0 ]; then
	echo $2
	exit 1
fi
}

if [ "$EUID" -eq 0 ]; then
	echo "Please run as current user"
	exit
fi

function dl_uninstall {
	if [ -z "$FOLD" ]; then
		FOLD=$TOOL
	fi

	echo -n "Uninstalling $TOOL... "
	cd $FOLD 2>/dev/null
	if [ "$?" -ne 0 ]; then
		echo "$TOOL not found!"
	else
		sudo make uninstall >/dev/null
		die "$?" "There was an error uninstalling $TOOL. EXITING!"
		echo "$TOOL successfully uninstalled!"
	fi
}

function uninstall_aircrack {
	(
		TOOL="aircrack-ng"
		dl_uninstall
	)
}

function uninstall_hcxtools {
	(
		TOOL="hcxtools"
		dl_uninstall
	)	
}

function uninstall_hcxdumptool {
	(
		TOOL="hcxdumptool"
		dl_uninstall
	)	
}

function uninstall_hashcat {
	(
		TOOL="hashcat"
		dl_uninstall
	)	
}

function uninstall_bully {
	(
		TOOL="bully"
		FOLD="bully/src"
		dl_uninstall
	)	
}

function uninstall_reaver {
	sudo rm -rf /usr/local/bin/wash /usr/local/bin/reaver /usr/local/var/lib/reaver
}

sudo ls >/dev/null
die "$?" "Sudo password not introduced. Exiting!"

cd sources 2>/dev/null
die "$?" "sources folder does not exist. Are you sure something is installed?"

uninstall_aircrack
uninstall_hcxtools
uninstall_reaver
uninstall_hcxdumptool
uninstall_hashcat
uninstall_bully
