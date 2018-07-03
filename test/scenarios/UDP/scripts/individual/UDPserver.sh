#!/bin/bash
tshark -i eth0 -w ~/scenario/UDP/imn/server/server.pcap&
while true; do echo -n "how are you?"; sleep 5; done |nc -k -u -l -p 89
