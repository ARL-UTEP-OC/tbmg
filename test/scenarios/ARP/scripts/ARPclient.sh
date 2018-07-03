#!/bin/bash
tshark -i eth0 -w ~/scenario/ARP/imn/both/client.pcap&
sleep 1
echo -n "hello" | nc -u 10.0.0.10 89 &
