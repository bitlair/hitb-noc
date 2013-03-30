#!/bin/bash
#
# T-Mobile DSLAM emulation on 7 VLANs
#

vconfig add eth0 20
vconfig add eth0 21
vconfig add eth0 22
vconfig add eth0 23
vconfig add eth0 24
vconfig add eth0 25
vconfig add eth0 26

ip addr add 212.64.109.1/24 dev eth0.20
ip addr add 212.64.109.1/24 dev eth0.21
ip addr add 212.64.110.1/24 dev eth0.22
ip addr add 212.64.110.1/24 dev eth0.23
ip addr add 212.64.110.1/24 dev eth0.24
ip addr add 212.64.110.1/24 dev eth0.25
ip addr add 212.64.110.1/24 dev eth0.26

ip link set eth0.20 up mtu 1492
ip link set eth0.21 up mtu 1492
ip link set eth0.22 up mtu 1492
ip link set eth0.23 up mtu 1492
ip link set eth0.24 up mtu 1492
ip link set eth0.25 up mtu 1492
ip link set eth0.26 up mtu 1492

ip route add 212.64.109.221 dev eth0.20
ip route add 212.64.109.241 dev eth0.21
ip route add 212.64.110.65 dev eth0.22
ip route add 212.64.110.124 dev eth0.23
ip route add 212.64.110.150 dev eth0.24
ip route add 212.64.110.173 dev eth0.25
ip route add 212.64.110.183 dev eth0.26
