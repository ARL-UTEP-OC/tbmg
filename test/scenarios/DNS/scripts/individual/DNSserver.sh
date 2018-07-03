#!/bin/bash
tshark -i eth0 -w ~/scenario/DNS/imn/server/server.pcap&
service bind9 restart
