#!/bin/bash

while true;do
	for i in $(seq 0 6);do
		pump -i br-uplink$i --no-setup &
		sleep 10
		killall -q -9 pump
	done
	sleep 60
done
