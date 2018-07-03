#!/bin/bash
tshark -i eth0 -w ~/scenario/HTTP/imn/client/client.pcap &
sleep 6
while true; do wget 10.0.0.10 80; sleep 3; done
