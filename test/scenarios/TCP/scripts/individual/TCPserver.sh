#!/bin/bash
tshark -i eth0 -w ~/scenario/TCP/imn/server/server.pcap&
while true; do echo -n "i'm listener"; sleep 5; done | nc -lp 81
