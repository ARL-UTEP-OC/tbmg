#!/bin/bash
tshark -i eth0 -w ~/scenario/ICMP/imn/client/client.pcap&
sleep 1
ping 10.0.0.10
