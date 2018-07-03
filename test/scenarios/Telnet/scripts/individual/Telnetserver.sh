#!/bin/bash
tshark -i eth0 -w ~/scenario/Telnet/imn/server/server.pcap &
twistd inetd
