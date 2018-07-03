#!/bin/bash
tshark -i eth0 -w ~/scenario/SIP/imn/both/server.pcap&
export TERM=xterm
sipp -sn uas
