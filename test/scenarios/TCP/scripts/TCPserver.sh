#!/bin/bash
tshark -i eth0 -w ~/scenario/TCP/imn/both/server.pcap&
while true; do echo -n "good evening"; sleep 5; done | nc -lp 81
