#!/bin/bash
tshark -i eth0 -w ~/scenario/FTP/imn/server/server.pcap&
twistd ftp -p 21
