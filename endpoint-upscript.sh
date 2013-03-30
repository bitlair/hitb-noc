#!/bin/bash
# 
# Hack in the Box tunnel script
# Off-site remote tunnel endpoint
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

TUNV4_IPFORMAT="10.239.0.%d" # %d is replaced by TUNV4_IPBASE + (tunnel number * 2)
TUNV4_IPBASE="242"
TUNV4_PREFIXLEN=31

TUNV6_IPFORMAT="2001:610:1337:ff%d::%d" # first %d is replaced by tunnel number, second by local/remote
TUNV6_PREFIXLEN=64

LINK_COUNT=7

TUN_LOCAL="192.168.1.1"
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

REMOTEV4_PREFIXES="10.10.0.0/16"
REMOTEV6_PREFIXES="2001:1af8::/48"



echo "Cleaning up old configuration..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	ip tunnel del tunv4-uplink$i
	ip tunnel del tunv6-uplink$i
done &>/dev/null
(pkill -9 bird
iptables -F
iptables -X
ip6tables -F
ip6tables -X
ipset destroy v4_local
ipset destroy v6_local
) &>/dev/null
echo "Making sure ARP replies are very strict about source interface..."
echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter
echo 2 > /proc/sys/net/ipv4/conf/all/arp_ignore

echo "Enabling packet forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding


echo "Defining the tunnel endpoint addresses..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	TUNV4_LOCAL[$i]=$(printf "${TUNV4_IPFORMAT}" $((${TUNV4_IPBASE} + ($i * 2))))
	TUNV4_REMOTE[$i]=$(printf "${TUNV4_IPFORMAT}" $((${TUNV4_IPBASE} + ($i * 2) + 1)))
	TUNV6_LOCAL[$i]=$(printf "${TUNV6_IPFORMAT}" $i 1)
	TUNV6_REMOTE[$i]=$(printf "${TUNV6_IPFORMAT}" $i 2)
done

echo "Creating the tunnel interfaces..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	ip tunnel add tunv4-uplink$i mode ipip remote ${TUN_REMOTE[$i]} local ${TUN_LOCAL}
	ip link set tunv4-uplink$i up mtu 1472
	ip -4 addr add ${TUNV4_LOCAL[$i]} peer ${TUNV4_REMOTE[$i]} dev tunv4-uplink$i
	ip tunnel add tunv6-uplink$i mode sit remote ${TUN_REMOTE[$i]} local ${TUN_LOCAL}
	ip link set tunv6-uplink$i up mtu 1472

	# This hack is necessary because Linux 6in4 ipv6 link-local is /128
	ip -6 addr flush dev tunv6-uplink$i
	ip -6 addr add fe80::$i:1/64 dev tunv6-uplink$i

	ip -6 addr add ${TUNV6_LOCAL[$i]}/${TUNV6_PREFIXLEN} dev tunv6-uplink$i
done

echo "Turning on MSS clamping for the tunnel interfaces..."
for i in $(seq 0 $((${LINK_COUNT}-1))); do
	# MSS 1432: 1492 (dsl) - 20 (ipv4) - 20 (ipv4) - 20 (TCP)
	iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o tunv4-uplink$i -j TCPMSS --set-mss 1432
 	# MSS 1412: 1492 (dsl) - 20 (ipv4) - 40 (ipv6) - 20 (TCP)
	ip6tables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o tunv6-uplink$i -j TCPMSS --set-mss 1412
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
	iptables -A FORWARD -i tunv4-uplink$i -m set --match-set v4_local src -j ACCEPT
	iptables -A FORWARD -i tunv4-uplink$i -j DROP

	ip6tables -A FORWARD -i tunv6-uplink$i -m set --match-set v6_local src -j ACCEPT
	ip6tables -A FORWARD -i tunv6-uplink$i -j DROP
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
