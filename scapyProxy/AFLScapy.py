from __future__ import print_function
import afl
from scapy.all import *
import json
from collections import defaultdict
import os
import threading
import time
from StringIO import StringIO

class FuzzPacket:
    def __init__(self,packet_,tbmg_=None,packet_feilds_=[]):
        self.packet = packet_
        self.tbmg = tbmg_
        self.packet_feilds = packet_feilds_ # = [('IP','dst'),('IP','id'),('ICMP','id'),...]
        self.output_dir = '/root/tbmg/afl_output/'+str(self.packet.time)  # may switch to /run/shm/ (RAM dir) because many R/W ops
        self.input_dir = '/root/tbmg/afl_testcases/'+str(self.packet.time)
        self.input_name = self.input_dir + '/afl_input'
        self.wrapper_name = 'packet_fuzz_wrapper.py'
        self.cmd = 'py-afl-fuzz -m 500 -t 20000+ -i ' + self.input_dir + ' -o ' + self.output_dir + ' -- python ' + self.wrapper_name
        
    def startScapyFuzz(self):
        layers = []
        for layer_num in range(10):
            try:
                layers.append(self.packet[layer_num].__class__)
            except IndexError:
                continue
        while 1:
            to_send = self.packet.copy()
            fuzzed_packet = None
            for layer in layers:
                if not fuzzed_packet:
                    fuzzed_packet = fuzz(layer())
                else:
                    fuzzed_packet = fuzzed_packet/fuzz(layer())
            if self.packet_feilds:
                for feild in self.packet_feilds:
                    setattr(to_send[feild[0]], feild[1], getattr(fuzzed_packet[feild[0]], feild[1]))
            else:
                to_send = fuzzed_packet
            try:
                del (to_send['IP'].chksum)
            except:
                pass
            try:
                del (to_send['TCP'].chksum)
            except:
                pass
            print('sending:')
            to_send.show2()
            response = sr1(to_send, timeout=3, verbose=0)
            if response:
                print('got:')
                response.show()
            else:
                print('no response')
                
    def startAFLFuzz(self):
        if not os.path.exists(self.input_dir):
            os.makedirs(self.input_dir)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
        if not self.packet_feilds:
            afl_input = open(self.input_name + 'packetHex.txt', 'w')
            afl_input.write(raw(self.packet).encode('hex'))
            afl_input.close()
        else:
            afl_input = open(self.input_name + 'packetFeilds.txt', 'w')
            for feild in self.packet_feilds:
                afl_input.write(
                    str(getattr(self.packet[feild[0]], feild[1])) + '\n')  # should i put this or a random/fuzzed value?
            afl_input.close()
            org_packet = open('org_packet.txt','w')
            org_packet.write(raw(self.packet).encode('hex'))
            org_packet.close()
            pack_feilds = open('packet_feilds.txt','w')
            pack_feilds.write(str(self.packet_feilds))
            pack_feilds.close()
        
        print ('running:', self.cmd)
        #os.system(self.cmd)#might have to pipe this into a terminal proc
        

if __name__ == '__main__':
    print ('running me')
    p = IP(dst="8.8.8.8")/ICMP()
    f = FuzzPacket(p, packet_feilds_=[('IP', 'ttl')])
    f.startAFLFuzz()
    #f.startScapyFuzz()