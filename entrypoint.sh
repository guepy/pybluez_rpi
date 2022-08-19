#!/bin/sh

service dbus start
service bluetooth start

./rpi_main_server_RFID.py -t 5
