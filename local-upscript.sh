#!/bin/bash
# 
# Hack in the Box tunnel script
# On-site local tunnel endpoint
#
# Needs linux kernel 3.7 or later because of ECMP for IPv6
# Needs iproute >= 20121211, because of nexthop for IPv6
#
# Copyright (C) Wilco Baan Hofman
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



TUN_REMOTE="194.171.96.105"

TUNV4_IPFORMAT="145.220.15.%d" # first %d is replaced by tunnel number, second by local/remote
TUNV4_IPBASE="240"
TUNV4_PREFIXLEN=24

TUNV6_IPFORMAT="2001:470:7945:ff%02d::%d" # first %d is replaced by tunnel number, second by local/remote
TUNV6_PREFIXLEN=64


REMOTEV4_PREFIXES="145.220.8.0/21"
REMOTEV6_PREFIXES="2001:470:7945::/48"

LINK_COUNT="7"
BOND_INTERFACE="bond0"
BOND_SLAVES="eth0 eth1"
BOND_NATIVE_V4_ADDRESS=""
BOND_NATIVE_V6_ADDRESS=""
VLAN_BASE="20"

TABLE_BASE="10"

ADDRESS[0]="212.64.109.221"
PREFIX[0]="24"
NETWORK[0]="212.64.109.0"
GATEWAY[0]="212.64.109.1"
WEIGHT[0]="100"
ADDRESS[1]="212.64.109.241"
PREFIX[1]="24"
NETWORK[1]="212.64.109.0"
GATEWAY[1]="212.64.109.1"
WEIGHT[1]="100"
ADDRESS[2]="212.64.110.65"
PREFIX[2]="24"
NETWORK[2]="212.64.110.0"
GATEWAY[2]="212.64.110.1"
WEIGHT[2]="100"
ADDRESS[3]="212.64.110.124"
PREFIX[3]="24"
NETWORK[3]="212.64.110.0"
GATEWAY[3]="212.64.110.1"
WEIGHT[3]="100"
ADDRESS[4]="212.64.110.150"
PREFIX[4]="24"
NETWORK[4]="212.64.110.0"
GATEWAY[4]="212.64.110.1"
WEIGHT[4]="100"
ADDRESS[5]="212.64.110.173"
PREFIX[5]="24"
NETWORK[5]="212.64.110.0"
GATEWAY[5]="212.64.110.1"
WEIGHT[5]="100"
ADDRESS[6]="212.64.110.183"
PREFIX[6]="24"
NETWORK[6]="212.64.110.0"
GATEWAY[6]="212.64.110.1"
WEIGHT[6]="100"


echo "Cleaning up old configuration..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	ip link set br-uplink$i down && 
		brctl delbr br-uplink$i
	vconfig rem vlan-uplink$i
	ip route flush table $((TABLE_BASE+$i)) 
	ip rule del from ${ADDRESS[$i]} table $((TABLE_BASE+$i))
	ip tunnel del tunv4-uplink$i
	ip tunnel del tunv6-uplink$i
done &>/dev/null
ip link set ${BOND_INTERFACE} down
pkill -9 bird
pkill -9 dhcpcd
iptables -F
iptables -X
ip6tables -F
ip6tables -X

echo "Making sure ARP replies are very strict about source interface..."
echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter
echo 1 > /proc/sys/net/ipv4/conf/all/arp_announce
echo 2 > /proc/sys/net/ipv4/conf/all/arp_ignore

echo "Enabling packet forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

echo "Configuring the bonding interface..."
rmmod bonding &>/dev/null
modprobe bonding mode=802.3ad # LACP
ip link set up ${BOND_INTERFACE}
ifenslave ${BOND_INTERFACE} ${BOND_SLAVES}
if [ ! -z "${BOND_NATIVE_V4_ADDRESS}" ]; then
	ip -4 addr add ${BOND_NATIVE_V4_ADDRESS} dev ${BOND_INTERFACE}
fi
if [ ! -z "${BOND_NATIVE_V6_ADDRESS}" ]; then
	ip -6 addr add ${BOND_NATIVE_V6_ADDRESS} dev ${BOND_INTERFACE}
fi

echo "Creating the VLAN interfaces, bridges and tables..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do

	# Create and name the VLAN interface
	vconfig add ${BOND_INTERFACE} $((${VLAN_BASE}+$i))
	ip link set ${BOND_INTERFACE}.$((${VLAN_BASE}+$i)) up name vlan-uplink$i

	# Create and link the corresponding bridge
	brctl addbr br-uplink$i
	brctl addif br-uplink$i vlan-uplink$i
	ip link set br-uplink$i up address $(printf "06:00:00:00:00:%02x" $i) mtu 1492 # DSL

	# Add the IP to the bridge interface
	ip -4 addr add ${ADDRESS[$i]}/${PREFIX[$i]} scope link dev br-uplink$i

	# Make sure traffic is routed to the proper table
	ip -4 rule add from ${ADDRESS[$i]} table $((TABLE_BASE+$i)) 

	# Populate the uplink routing table
	ip -4 route add ${NETWORK[$i]}/${PREFIX[$i]} dev br-uplink$i table $((TABLE_BASE+$i))
	ip -4 route add 0.0.0.0/0 via ${GATEWAY[$i]} dev br-uplink$i table $((TABLE_BASE+$i))
done

echo "Spoofing the DHCP handshakes..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	dhcpcd -TRYN br-uplink$i &>/dev/null &
done

echo "Defining the tunnel endpoint addresses..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	TUNV4_LOCAL[$i]=$(printf "${TUNV4_IPFORMAT}" $((${TUNV4_IPBASE} + ($i * 2) + 1)))
	TUNV4_REMOTE[$i]=$(printf "${TUNV4_IPFORMAT}" $((${TUNV4_IPBASE} + ($i * 2))))
	TUNV6_LOCAL[$i]=$(printf "${TUNV6_IPFORMAT}" $i 2)
	TUNV6_REMOTE[$i]=$(printf "${TUNV6_IPFORMAT}" $i 1)
done

echo "Creating the tunnel interfaces..."
# Dummy route to make sure the packet reaches the IP rules
ip -4 route add ${TUN_REMOTE} via ${GATEWAY[1]} dev br-uplink1 table main

for i in $(seq 0 $((${LINK_COUNT}-1))); do
	ip tunnel add tunv4-uplink$i mode ipip remote ${TUN_REMOTE} local ${ADDRESS[$i]}
	ip link set tunv4-uplink$i up mtu 1472 # 1492 (dsl) - 20 (ipv4)
	ip -4 addr add ${TUNV4_LOCAL[$i]} peer ${TUNV4_REMOTE[$i]} dev tunv4-uplink$i
	ip tunnel add tunv6-uplink$i mode sit remote ${TUN_REMOTE} local ${ADDRESS[$i]}
	ip link set tunv6-uplink$i up mtu 1472 # 1492 (dsl) - 20 (ipv4)

	# This hack is necessary because Linux 6in4 link-local is /128
	ip -6 addr flush dev tunv6-uplink$i
	ip -6 addr add fe80::$i:2/64 dev tunv6-uplink$i
	
	ip -6 addr add ${TUNV6_LOCAL[$i]}/${TUNV6_PREFIXLEN} dev tunv6-uplink$i
done

echo "Turning on MSS clamping for the tunnel interfaces..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	# MSS 1432: 1492 (dsl) - 20 (ipv4) - 20 (ipv4) - 20 (TCP)
	iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o tunv4-uplink$i -j TCPMSS --set-mss 1432
 	# MSS 1412: 1492 (dsl) - 20 (ipv4) - 40 (ipv6) - 20 (TCP)
	ip6tables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o tunv6-uplink$i -j TCPMSS --set-mss 1412
done

echo "Configuring and starting OSPFv2 daemon..."
cat > /tmp/bird.conf << EOF
# Configure logging
log syslog { debug, trace, info, remote, warning, error, auth, fatal, bug };

# Override router ID
router id 2;

filter hitb_local_routes {
EOF
for prefix in ${REMOTEV4_PREFIXES};do
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
  scan time 10;         # Scan interfaces every 10 seconds
}

protocol static {
  import all;
EOF
for prefix in ${REMOTEV4_PREFIXES};do
	echo "route ${prefix} blackhole; # Not really, but we announce it!"
done >> /tmp/bird.conf
cat >> /tmp/bird.conf << EOF
}

protocol ospf MyOSPF {
  import all;
  export filter hitb_local_routes;
  tick 2;
  rfc1583compat yes;
  ecmp yes;
  area 0 {
EOF
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	echo "    interface \"tunv4-uplink$i\" {"
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
router id 2;

filter hitb_local_routes {
EOF
for prefix in ${REMOTEV6_PREFIXES};do
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
  scan time 10;         # Scan interfaces every 10 seconds
}

protocol static {
  import all;
EOF
for prefix in ${REMOTEV6_PREFIXES};do
	echo "route ${prefix} blackhole; # Not really, but we announce it!"
done >> /tmp/bird6.conf
cat >> /tmp/bird6.conf << EOF
}

protocol ospf MyOSPF {
  import all;
  export filter hitb_local_routes;
  tick 2;
  rfc1583compat yes;
  ecmp yes;
  area 0 {
EOF
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	echo "    interface \"tunv6-uplink$i\" {"
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
