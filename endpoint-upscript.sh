#!/bin/bash
# 
# Hack in the Box tunnel script
# Off-site remote tunnel endpoint
#
# Needs linux kernel 3.7 or later because of ECMP for IPv6
# Needs iproute >= 20121211, because of nexthop for IPv6
#
# Copyright (C) 2013 by Wilco Baan Hofman 
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>
#

TUNV4_IPFORMAT="145.220.15.%d" # %d is replaced by TUNV4_IPBASE + (tunnel number * 2)
TUNV4_IPBASE="240"
TUNV4_PREFIXLEN=31

TUNV6_IPFORMAT="2001:470:7945:ff%02d::%d" # first %d is replaced by tunnel number, second by local/remote
TUNV6_PREFIXLEN=64

UPLINK_INTERFACE="eth1"
UPLINKV4_ADDRESS="145.220.15.6"
UPLINKV4_PREFIXLEN="30"
UPLINKV4_GATEWAY="145.220.15.5"
UPLINKV4_SUBNET="145.220.8.0/21"
UPLINKV6_ADDRESS="2001:610:16f:ffff::2"
UPLINKV6_PREFIXLEN="64"
UPLINKV6_GATEWAY="2001:610:16f:ffff::1"
UPLINKV6_SUBNET="2001:610:16f::/48"

DNLINK_INTERFACE="eth0"
DNLINKV4_ADDRESS="194.171.96.105"
DNLINKV4_PREFIXLEN="27"
DNLINKV4_GATEWAY="194.171.96.126"
DNLINKV4_EXTRA_ROUTE_BACKDOOR="192.16.185.188"

TUNV6_UPLINK_REMOTE="216.66.84.46"
TUNV6_UPLINK_ADDRESS="2001:470:1f14:17d::2/64"
TUNV6_SUBNET="2001:470:7945::/48"

TUNV4_BITLAIR_REMOTE="83.87.111.232"
TUNV4_BITLAIR_ADDRESS="145.220.15.10"
TUNV4_BITLAIR_PEER="145.220.15.11"
TUNV4_BITLAIR_SUBNET="192.168.88.0/24"


LINK_COUNT=7

TUN_REMOTE[0]="212.64.109.221"
TUN_REMOTE[1]="212.64.109.241"
TUN_REMOTE[2]="212.64.110.65"
TUN_REMOTE[3]="212.64.110.124"
TUN_REMOTE[4]="212.64.110.150"
TUN_REMOTE[5]="212.64.110.173"
TUN_REMOTE[6]="212.64.110.183"
WEIGHT[0]="100"
WEIGHT[1]="100"
WEIGHT[2]="100"
WEIGHT[3]="100"
WEIGHT[4]="100"
WEIGHT[5]="100"
WEIGHT[6]="100"

REMOTEV4_PREFIXES="${UPLINKV4_SUBNET}"
REMOTEV6_PREFIXES="${TUNV6_SUBNET} ${UPLINKV6_SUBNET}"

echo "Cleaning up old configuration..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	ip tunnel del tunv4-dnlink$i
	ip tunnel del tunv6-dnlink$i
	ip -4 route del ${TUN_REMOTE[$i]} via ${DNLINKV4_GATEWAY}
done &>/dev/null
(pkill -9 bird
iptables -F
iptables -X
ip6tables -F
ip6tables -X
ipset destroy v4_local
ipset destroy v6_local
ip link set down dev ${UPLINK_INTERFACE}
ip link set name uplink dev ${UPLINK_INTERFACE}
ip addr flush dev uplink
ip link set up dev uplink
ip link set down dev ${DNLINK_INTERFACE}
ip link set name dnlink dev ${DNLINK_INTERFACE}
ip addr flush dev dnlink
ip link set up dev dnlink
ip tunnel del tunv6-uplink
ip -6 rule del from ${UPLINKV6_SUBNET} table 101 
ip tunnel del tunv4-bitlair
ip -4 route del ${TUNV4_BITLAIR_REMOTE}
) &>/dev/null
echo "Making sure ARP replies are very strict about source interface..."
echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter
echo 2 > /proc/sys/net/ipv4/conf/all/arp_ignore

echo "Enabling packet forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

echo "Configuring uplink interface..."
ip -4 addr add ${UPLINKV4_ADDRESS}/${UPLINKV4_PREFIXLEN} dev uplink
ip -4 route add default via ${UPLINKV4_GATEWAY} dev uplink
ip -6 addr add ${UPLINKV6_ADDRESS}/${UPLINKV6_PREFIXLEN} dev uplink
ip -6 route add default via ${UPLINKV6_GATEWAY} dev uplink table 101
ip -6 rule add from ${UPLINKV6_SUBNET} table 101

echo "Configuring dnlink interface..."
ip -4 addr add ${DNLINKV4_ADDRESS}/${DNLINKV4_PREFIXLEN} dev dnlink
ip -4 route add ${DNLINKV4_EXTRA_ROUTE_BACKDOOR} via ${DNLINKV4_GATEWAY} dev dnlink


echo "Configuring HE uplink..."
ip -4 route add ${TUNV6_UPLINK_REMOTE} via ${DNLINKV4_GATEWAY} src ${DNLINKV4_ADDRESS}
ip tunnel add tunv6-uplink mode sit remote ${TUNV6_UPLINK_REMOTE} local ${DNLINKV4_ADDRESS}
ip link set tunv6-uplink up mtu 1472
ip -6 addr add ${TUNV6_UPLINK_ADDRESS} dev tunv6-uplink
ip -6 route add ::/0 dev tunv6-uplink

echo "Configuring bitlair tunnel..."
ip -4 route add ${TUNV4_BITLAIR_REMOTE} via ${DNLINKV4_GATEWAY}
ip tunnel add tunv4-bitlair mode ipip remote ${TUNV4_BITLAIR_REMOTE} local ${DNLINKV4_ADDRESS}
ip link set tunv4-bitlair up mtu 1472
ip -4 addr add ${TUNV4_BITLAIR_ADDRESS} peer ${TUNV4_BITLAIR_PEER} dev tunv4-bitlair
ip -4 route add ${TUNV4_BITLAIR_SUBNET} dev tunv4-bitlair


echo "Defining the tunnel endpoint addresses..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	TUNV4_LOCAL[$i]=$(printf "${TUNV4_IPFORMAT}" $((${TUNV4_IPBASE} + ($i * 2))))
	TUNV4_REMOTE[$i]=$(printf "${TUNV4_IPFORMAT}" $((${TUNV4_IPBASE} + ($i * 2) + 1)))
	TUNV6_LOCAL[$i]=$(printf "${TUNV6_IPFORMAT}" $i 1)
	TUNV6_REMOTE[$i]=$(printf "${TUNV6_IPFORMAT}" $i 2)
done

echo "Creating the tunnel interfaces..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	ip -4 route add ${TUN_REMOTE[$i]} via ${DNLINKV4_GATEWAY}
	ip tunnel add tunv4-dnlink$i mode ipip remote ${TUN_REMOTE[$i]} local ${DNLINKV4_ADDRESS}
	ip link set tunv4-dnlink$i up mtu 1472
	ip -4 addr add ${TUNV4_LOCAL[$i]} peer ${TUNV4_REMOTE[$i]} dev tunv4-dnlink$i
	ip tunnel add tunv6-dnlink$i mode sit remote ${TUN_REMOTE[$i]} local ${DNLINKV4_ADDRESS}
	ip link set tunv6-dnlink$i up mtu 1472

	# This hack is necessary because Linux 6in4 ipv6 link-local is /128
	ip -6 addr flush dev tunv6-dnlink$i
	ip -6 addr add fe80::$i:1/64 dev tunv6-dnlink$i

	ip -6 addr add ${TUNV6_LOCAL[$i]}/${TUNV6_PREFIXLEN} dev tunv6-dnlink$i
done

echo "Turning on MSS clamping for the tunnel interfaces..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	# MSS 1432: 1492 (dsl) - 20 (ipv4) - 20 (ipv4) - 20 (TCP)
	iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o tunv4-dnlink$i -j TCPMSS --set-mss 1432
 	# MSS 1412: 1492 (dsl) - 20 (ipv4) - 40 (ipv6) - 20 (TCP)
	ip6tables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o tunv6-dnlink$i -j TCPMSS --set-mss 1412
done

echo "Configuring ip sets..."
ipset create v4_local hash:net family inet
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	ipset add v4_local ${TUNV4_REMOTE[$i]}/${TUNV4_PREFIXLEN}
done
for prefix in ${REMOTEV4_PREFIXES}; do
	ipset add v4_local ${prefix}
done

ipset create v6_local hash:net family inet6
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	ipset add v6_local ${TUNV6_REMOTE[$i]}/${TUNV6_PREFIXLEN}
done
for prefix in ${REMOTEV6_PREFIXES}; do
	ipset add v6_local ${prefix}
done

echo "Configuring tunnel interface inbound firewall..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	iptables -A FORWARD -i tunv4-dnlink$i -m set --match-set v4_local src -j ACCEPT
	iptables -A FORWARD -i tunv4-dnlink$i -j DROP

	ip6tables -A FORWARD -i tunv6-dnlink$i -m set --match-set v6_local src -j ACCEPT
	ip6tables -A FORWARD -i tunv6-dnlink$i -j DROP
done

echo "Configuring and starting OSPFv2 daemon..."
cat > /tmp/bird.conf << EOF
# Configure logging
log syslog { debug, trace, info, remote, warning, error, auth, fatal, bug };

# Override router ID
router id 1;

filter hitb_local_routes {
EOF
for prefix in ${REMOTEV4_PREFIXES}; do
	echo "  if net ~ ${prefix} then accept;"
done >> /tmp/bird.conf
cat >> /tmp/bird.conf << EOF
  else reject;
}

filter non_static {
  if source = RTS_STATIC then reject;
  else accept;
}

#debug protocols all;

protocol kernel {
  import none;
  export filter non_static;
}

protocol device {
  scan time 10;		# Scan interfaces every 10 seconds
}

protocol static {
  import all;
  route 0.0.0.0/0 blackhole; # Not really, but we announce it!
}

protocol ospf MyOSPF {
  export all;
  import filter hitb_local_routes;
  tick 2;
  rfc1583compat yes;
  ecmp yes;
  area 0 {
EOF
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	echo "    interface \"tunv4-dnlink$i\" {"
	echo "      ecmp weight ${WEIGHT[$i]};"
	echo "      type nonbroadcast;"
	echo "      neighbors {"
	echo "        ${TUNV4_REMOTE[$i]} eligible;"
	echo "      };"
	echo "      strict nonbroadcast no;"
	echo "    };"
done >> /tmp/bird.conf
cat >> /tmp/bird.conf << EOF
  };
}
EOF
/usr/sbin/bird -c /tmp/bird.conf

echo "Configuring and starting OSPFv3 daemon..."
cat > /tmp/bird6.conf << EOF
# Configure logging
log syslog { debug, trace, info, remote, warning, error, auth, fatal, bug };

# Override router ID
router id 1;

filter hitb_local_routes {
EOF
for prefix in ${REMOTEV6_PREFIXES}; do
	echo "  if net ~ ${prefix} then accept;"
done >> /tmp/bird6.conf
cat >> /tmp/bird6.conf << EOF
  else reject;
}

filter non_static {
  if source = RTS_STATIC then reject;
  else accept;
}

#debug protocols all;

protocol kernel {
  import none;
  export filter non_static;
}

protocol device {
  scan time 10;		# Scan interfaces every 10 seconds
}

protocol static {
  import all;
  route ::/0 blackhole; # Not really, but we announce it!
}

protocol ospf MyOSPF {
  export all;
  import filter hitb_local_routes;
  tick 2;
  rfc1583compat yes;
  ecmp yes;
  area 0 {
EOF
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	echo "    interface \"tunv6-dnlink$i\" {"
	echo "      ecmp weight ${WEIGHT[$i]};"
	echo "      type nonbroadcast;"
	echo "      neighbors {"
	echo "        ${TUNV6_REMOTE[$i]} eligible;"
	echo "      };"
	echo "      strict nonbroadcast no;"
	echo "    };"
done >> /tmp/bird6.conf
cat >> /tmp/bird6.conf << EOF
  };
}
EOF
/usr/sbin/bird6 -c /tmp/bird6.conf
