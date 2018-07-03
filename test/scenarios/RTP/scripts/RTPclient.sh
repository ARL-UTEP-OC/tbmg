#!/bin/bash
tshark -i eth0 -w ~/scenario/RTP/imn/both/client.pcap&
sleep 3
#SUDO_UID=1000 vlc-wrapper rtp://239.255.12.42
su -c "cvlc rtp://239.255.12.42" tym
