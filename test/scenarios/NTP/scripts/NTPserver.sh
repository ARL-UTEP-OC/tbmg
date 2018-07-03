#!/bin/bash
tshark -i eth0 -w ~/scenario/NTP/imn/both/server.pcap&
/etc/init.d/ntp restart
