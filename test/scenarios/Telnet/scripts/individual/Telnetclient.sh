#!/bin/bash
tshark -i eth0 -w ~/scenario/Telnet/imn/client/client.pcap&
sleep 1
telnet 10.0.0.10
