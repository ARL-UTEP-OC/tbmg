#!/bin/bash
tshark -i eth0 -w ~/scenario/NTP/imn/both/client.pcap&
sleep 1
ntpdate 10.0.0.10
