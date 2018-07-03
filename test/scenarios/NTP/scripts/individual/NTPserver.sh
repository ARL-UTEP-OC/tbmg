#!/bin/bash
tshark -i eth0 -w ~/scenario/NTP/imn/server/server.pcap&
/etc/init.d/ntp restart
