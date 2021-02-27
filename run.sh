#!/usr/bin/sh


cargo build
cd target/debug/ || exit
sudo ./linkage_cli connect -c Prague.ovpn
