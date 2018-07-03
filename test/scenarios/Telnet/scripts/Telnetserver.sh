#!/bin/bash
tshark -i eth0 -w ~/scenario/Telnet/imn/both/server.pcap &
twistd inetd
