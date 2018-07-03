#!/bin/bash
tshark -i eth0 -w ~/scenario/TCP_IP/imn/both/server.pcap&
nc -lp 81
