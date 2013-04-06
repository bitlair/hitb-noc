#!/bin/bash
#
# T-Mobile DSLAM emulation on 7 VLANs
#

vconfig add eth0 700
vconfig add eth0 701
vconfig add eth0 702
vconfig add eth0 703
vconfig add eth0 704
vconfig add eth0 705
vconfig add eth0 706

ip addr add 212.64.109.1/24 dev eth0.700
ip addr add 212.64.109.1/24 dev eth0.701
ip addr add 212.64.110.1/24 dev eth0.702
ip addr add 212.64.110.1/24 dev eth0.703
ip addr add 212.64.110.1/24 dev eth0.704
ip addr add 212.64.110.1/24 dev eth0.705
ip addr add 212.64.110.1/24 dev eth0.706

ip link set eth0.700 up mtu 1492
ip link set eth0.701 up mtu 1492
ip link set eth0.702 up mtu 1492
ip link set eth0.703 up mtu 1492
ip link set eth0.704 up mtu 1492
ip link set eth0.705 up mtu 1492
ip link set eth0.706 up mtu 1492

ip route add 212.64.109.221 dev eth0.700
ip route add 212.64.109.241 dev eth0.701
ip route add 212.64.110.65 dev eth0.702
ip route add 212.64.110.124 dev eth0.703
ip route add 212.64.110.150 dev eth0.704
ip route add 212.64.110.173 dev eth0.705
ip route add 212.64.110.183 dev eth0.706
