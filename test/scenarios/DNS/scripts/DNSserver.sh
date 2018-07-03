#!/bin/bash
tshark -i eth0 -w ~/scenario/DNS/imn/both/server.pcap&
service bind9 restart
