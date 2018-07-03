#!/bin/bash
tshark -i eth0 -w ~/scenario/IGMP/imn/both/server.pcap&
sleep 1
ip route add 224.225.1/24 dev eth0
mgen input test2.mgn
