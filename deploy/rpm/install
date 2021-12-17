#!/bin/sh

APP_ROOT=/usr/local/fw
SYSTEMD_ROOT=/usr/lib/systemd/system

function systemd_install() {
	app=$1
	app_unit=$APP_ROOT/$app.service

	if ! diff -q $app_unit $SYSTEMD_ROOT/$app.service &> /dev/null ; then
		echo "install $SYSTEMD_ROOT/$app.service, please start it manual by 'systemctl start $app'"
		cp -f $app_unit $SYSTEMD_ROOT/
		mkdir -p $APP_ROOT/bin/
		systemctl enable --force $app.service
		systemctl daemon-reload
	fi
}

systemd_install fw
