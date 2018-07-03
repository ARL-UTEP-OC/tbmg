#!/bin/bash
tshark -i eth0 -w ~/scenario/SIP/imn/client/client.pcap&
export TERM=xterm
sleep 3
sipp -sn uac 10.0.0.10
