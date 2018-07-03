#!/bin/bash
tshark -i eth0 -w ~/scenario/TCP/imn/client/client.pcap&
sleep 1
while true; do echo -n "i'm sender"; sleep 5; done | nc 10.0.0.10 81&
