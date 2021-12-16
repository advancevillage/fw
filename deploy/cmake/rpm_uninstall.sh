#!/bin/sh

function systemd_uninstall() {
	app=$1
	if systemctl is-active $app.service; then
		systemctl stop $app.service
	fi

	if systemctl is-active $app.service; then
		systemctl disable $app.service
	fi

	rm -f /usr/lib/systemd/system/$app.service
	systemctl daemon-reload
}

if [ $1 -eq 0 ] ; then
	echo "fw systemd service units are removed."
	systemd_uninstall fw
fi
