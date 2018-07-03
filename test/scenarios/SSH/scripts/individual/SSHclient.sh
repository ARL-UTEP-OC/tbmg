#!/bin/bash
tshark -i eth0 -w ~/scenario/SSH/imn/client/client.pcap&
sleep 1
rm /root/.ssh/known_hosts 
ssh 10.0.0.10
sleep 1


