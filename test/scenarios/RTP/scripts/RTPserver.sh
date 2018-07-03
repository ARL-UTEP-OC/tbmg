#!/bin/bash
tshark -i eth0 -w ~/scenario/RTP/imn/both/server.pcap&
sleep 2
#SUDO_UID=1000 vlc-wrapper --loop office.mp3 --sout '#transcode{vcodec=mp4v,acodec=mpga,vb=800,ab=128,deinterlace}:duplicate{dst=display,dst=rtp{mux=ts,dst=239.255.12.42,sdp=sap,name="TestStream"}}'
su -c "cvlc --loop office.mp3 --sout '#transcode{vcodec=mp4v,acodec=mpga,vb=800,ab=128,deinterlace}:duplicate{dst=display,dst=rtp{mux=ts,dst=239.255.12.42,sdp=sap,name="TestStream"}}'" ned
