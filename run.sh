#!/usr/bin/sh


cargo build
cd target/debug/ || exit
sudo ./linkage_cli -c Prague.ovpn
