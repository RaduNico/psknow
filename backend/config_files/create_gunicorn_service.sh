#!/bin/bash


if [ "$?" -ne 0 ]; then
	echo "You need to be root you dummy" >&2
	exit -1
fi

cp gunicorn.service /etc/systemd/system/backend.service
chown root /etc/systemd/system/backend.service
chgrp root /etc/systemd/system/backend.service
chmod 644 /etc/systemd/system/backend.service
