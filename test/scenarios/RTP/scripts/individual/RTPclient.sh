#!/bin/bash
tshark -i eth0 -w ~/scenario/RTP/imn/client/client.pcap&
sleep 1
cvlc rtp://239.255.12.42
