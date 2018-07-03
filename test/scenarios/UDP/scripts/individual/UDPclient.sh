#!/bin/bash
tshark -i eth0 -w ~/scenario/UDP/imn/client/client.pcap&
sleep 1
while true; do echo -n "hello"; sleep 5; done | nc -u 10.0.0.10 89 &
