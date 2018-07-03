#!/bin/bash
tshark -i eth0 -w ~/scenario/FTP/imn/both/server.pcap&
twistd ftp -p 21
