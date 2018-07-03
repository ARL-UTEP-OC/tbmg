#!/bin/bash
tshark -i eth0 -w ~/scenario/DNS/imn/both/client.pcap&
sleep 1
while true; do dig @10.0.0.10 localhost; sleep 3; done
