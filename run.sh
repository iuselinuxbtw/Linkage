#!/usr/bin/sh


cargo build
cd target/debug/ || exit
sudo ./linkage_cli connect -f Prague.ovpn
