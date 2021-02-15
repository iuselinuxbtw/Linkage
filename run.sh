#!/usr/bin/sh


cargo build
cd target/debug/
sudo ./linkage_cli -c Copenhagen.ovpn
