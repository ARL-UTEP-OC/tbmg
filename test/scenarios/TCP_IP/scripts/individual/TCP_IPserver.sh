#!/bin/bash
tshark -i eth0 -w ~/scenario/TCP_IP/imn/server/server.pcap&
nc -lp 81
