#!/bin/bash
tshark -i eth0 -w ~/scenario/FTP/imn/client/client.pcap&
sleep 1
ftp 10.0.0.10 21
