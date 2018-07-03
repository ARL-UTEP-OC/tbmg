#!/bin/bash
tshark -i eth0 -w ~/scenario/ARP/imn/both/server.pcap&
nc -k -u -l -p 89
