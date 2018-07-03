#!/bin/bash
tshark -i eth0 -w ~/scenario/Telnet/imn/both/client.pcap&
sleep 3
telnet 10.0.0.10 
