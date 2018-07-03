#!/bin/bash
tshark -i eth0 -w ~/scenario/UDP/imn/both/server.pcap&
while true; do echo -n "wuzzup"; sleep 4; done | nc -k -u -l -p 89
