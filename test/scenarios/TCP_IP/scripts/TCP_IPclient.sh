#!/bin/bash
tshark -i eth0 -w ~/scenario/TCP_IP/imn/both/client.pcap&
sleep 1
nc 10.0.0.10 81&
