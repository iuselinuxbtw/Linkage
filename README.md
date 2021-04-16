# Linkage
[![Tests](https://github.com/BitJerkers/Linkage/actions/workflows/tests.yml/badge.svg)](https://github.com/BitJerkers/Linkage/actions/workflows/tests.yml)
[![Build (Linux)](https://github.com/BitJerkers/Linkage/actions/workflows/build-linux.yml/badge.svg)](https://github.com/BitJerkers/Linkage/actions/workflows/build-linux.yml)

An open source VPN manager written in Rust, aimed at simplicity and security.

| :exclamation: This program is still in beta and we do not guarantee leak safety. Use at your own risk.|
|-------------------------------------------------------------------------------------------------------|

This does not mean that we didn't test it but we cannot guarantee that your system works as intended.
The software is provided as-is.


## Features
- Automatically sets up the firewall from an OpenVPN File 
- Automatically checks for IP leaks
- Automatically checks for DNS leaks


## How it works
This program uses iptables to set up the firewall, which blocks all traffic except the IP address and ports with the
protocol from the OpenVPN file while keeping established connections alive.

It checks whether the ip or dns leaks using the APIs from ipleak.net, you can exchange the provider in the code and
we plan to add more providers soon. When a leak is detected, the VPN will automatically disconnect.


## Download
You can download Linkage from [here](https://github.com/BitJerkers/Linkage/releases/)

Or you can build from source:
```shell
git clone -r https://github.com/BitJerkers/Linkage/
cd Linkage
make
sudo make install
```

## Usage

```shell
sudo linkage connect -f [config.ovpn]
```

To avoid the hassle of googling with your phone how to reset iptables, we recommend to also download the
reset_iptables.sh script, which will reset the iptables configuration to the default settings when executed.

## Configuration

:exclamation: Be careful with the IP addresses you add here, if you add your router for example you may create a DNS
leak.

The default configuration file is in: `.config/linkage/config`

And an example for a configuration file would be:

```shell
[[firewall.exception]]
host = "192.168.1.112"
port = 31
protocol = "TCP"

[[firewall.exception]]
host = "2607:f0d0:1002:51::4"
port = 187
protocol = "UDP"
```

But you can also parse another configuration file by using

`linkage connect -f [ovpn-file] -c [path_to_config_file]`

## TODO

- Add custom exceptions to the firewall.
- Add more providers for IP- and DNSLeak testing
- Add more firewalls
- Configuration files
- Import configurations into Linkage, which will automatically be adjusted (long term goal)
    - Provider support: They "provide" the configurations for Linkage from VPN providers, and integrate them into the
      application
