from __future__ import print_function
import afl
from scapy.all import *
import json
from collections import defaultdict
import os


class FuzzPacket:
    def __init__(self,packet_):
        self.packet = packet_
        self.output_dir = '/root/tbmg/afl_output'  # may switch to /run/shm/ (RAM dir) because many R/W ops
        self.input_dir = '/root/tbmg/afl_testcases'
        self.input_name = self.input_dir + '/afl_input' + str(self.packet.time) + '.txt'
        self.wrapper_name = 'packet_fuzz_wrapper.py'
        self.cmd = 'py-afl-fuzz -m 500 -t 20000+ -i ' + self.input_dir + ' -o ' + self.output_dir + ' -- python ' + self.wrapper_name
        self.setup()
        self.startFuzz()
        
    def setup(self):
        if not os.path.exists(self.input_dir):
            os.makedirs(self.input_dir)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        afl_input = open(self.input_name, 'w')
        afl_input.write(raw(self.packet).encode('hex'))
    
    def startFuzz(self):
        wrapper = open(self.wrapper_name,'w')
        wrapper.write('import sys\n')
        wrapper.write('from scapy.all import *\n')
        wrapper.write('def main():\n')
        wrapper.write('\ts = sys.stdin.read()\n')
        wrapper.write('\ttry:\n')
        wrapper.write('\t\tpkt = IP(s.decode("hex"))\n')#TODO handle eth,arp,ip
        wrapper.write('\t\tpkt.time = '+str(self.packet.time)+'\n')
        wrapper.write('\t\tresp = sr1(pkt)\n')
        wrapper.write('\t\tprint resp.summary()\n')
        wrapper.write('\texcept Exception as e:\n')
        wrapper.write('\t\tprint repr(e)\n')
        wrapper.write('\n')
        wrapper.write('if __name__ == "__main__":\n')
        wrapper.write('\timport afl\n')
        wrapper.write('\tafl.start()\n')
        wrapper.write('\tmain()\n')
        wrapper.close()
        print ('running:', self.cmd)
        os.system(self.cmd)#might have to pipe this into a terminal proc
        

if __name__ == '__main__':
    print ('running me')
    p = IP(dst="8.8.8.8")/ICMP()
    FuzzPacket(p)