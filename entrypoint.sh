#!/bin/sh

service dbus start
service bluetooth start

sudo sh -c "echo \"195.221.0.168 sun-si-pluss\" >> /etc/hosts"
./rpi_main_server_RFID.py -t 5
