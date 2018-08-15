from __future__ import print_function
from scapy.all import *
import json
from collections import defaultdict
import os
import threading
import time
from GuiUtils import VerticalScrolledFrame
from Tkinter import *
from multiprocessing import Process

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
        self.accept_me = []
        self.status = False
        self.red = '#e85151'
        self.green = '#76ef51'
        
    def startScapyFuzz(self):
        layers = []
        for layer_num in range(10):
            try:
                layers.append(self.packet[layer_num].__class__)
            except IndexError:
                continue
        while self.status:
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
            print('sending:', to_send.summary())
            self.accept_me.append(to_send)
            response = sendp(to_send)#sr1(to_send, timeout=3, verbose=0)
            time.sleep(.1)
            #if response:
            #    print('got:')
            #    response.show()
            #else:
            #    print('no response')
    '''
    def startAFLFuzz(self):
        import afl
        afl.start()
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
    '''
    def GUIstopFuzz(self):
        self.status = False
        for item in self.tbmg.page6.grid_slaves():
            item.destroy()
    
    def GUIstartFuzz(self):
        self.status = True
        self.packet_feilds=[]
        for layer in self.gui_layers:
            if layer == 'Ether' or layer == 'Ethernet':
                continue
            for item in self.gui_layers[layer]:
                try:
                    if item[3]['text'] == "T":
                        self.packet_feilds.append((item[0]['text'], item[1]['text']))
                except:
                    print ('item:', item)
                    pass
        print ('packet_feilds:', self.packet_feilds)
        p = threading.Thread(target=self.startScapyFuzz)
        p.setDaemon(True)
        p.start()
        #self.startScapyFuzz()
        

    def populateFuzzerGUI(self):
        self.tbmg.start_fuzz = Button(self.tbmg.page6, text='Start Fuzz', command=self.GUIstartFuzz)
        self.tbmg.start_fuzz.grid(row=0, column=0, sticky='NEWS')
        self.tbmg.stop_fuzz = Button(self.tbmg.page6, text='Stop Fuzz', command=self.GUIstopFuzz)
        self.tbmg.stop_fuzz.grid(row=0, column=1, sticky='NEWS')
        self.tbmg.packet_scroll = VerticalScrolledFrame(self.tbmg.page6, height=30, width=50)
        self.tbmg.packet_scroll.grid(row=1, column=0, columnspan=2)
        self.populatePacket()

    def populatePacket(self):
        def updateToggleButton(button):
            if button['text'] == 'F':
                button.configure(text='T', bg=self.green)
            else:
                button.configure(text='F', bg=self.red)
        self.gui_layers = {}
        rownum = 1
        # $pack.show()
        for i in range(10):
            try:
                l = self.packet.getlayer(i)
                if not l:
                    continue
                self.gui_layers[l.name] = []
            
                layer = Label(self.tbmg.packet_scroll.interior, text=l.name)
                if l.name in self.tbmg.scapybridgeS.proto_colors:
                    label.config(bg=self.tbmg.scapybridgeS.proto_colors[l.name])
                layer.grid(row=rownum, column=0)
                rownum += 1
                if l.name == 'Ethernet' or l.name == 'Ether':
                    label = Label(self.tbmg.packet_scroll.interior, text='src')
                    label.grid(row=rownum, column=1)
                    entry = Entry(self.tbmg.packet_scroll.interior, width=30)
                    entry.grid(row=rownum, column=2)
                    entry.insert(0, str(self.packet[0].src).encode('utf8'))
                    self.gui_layers[l.name].append((layer, label, entry))
                    rownum += 1
                
                    label = Label(self.tbmg.packet_scroll.interior, text='dst')
                    label.grid(row=rownum, column=1)
                    entry = Entry(self.tbmg.packet_scroll.interior, width=30)
                    entry.grid(row=rownum, column=2)
                    entry.insert(0, str(self.packet[0].dst).encode('utf8'))
                    self.gui_layers[l.name].append((layer, label, entry))
                    rownum += 1
                
                    label = Label(self.tbmg.packet_scroll.interior, text='type')
                    label.grid(row=rownum, column=1)
                    entry = Entry(self.tbmg.packet_scroll.interior, width=30)
                    entry.grid(row=rownum, column=2)
                    entry.insert(0, str(self.packet[0].type).encode('utf8'))
                    self.gui_layers[l.name].append((layer, label, entry))
                    rownum += 1
                    continue
                
                for f in l.fields:
                    label = Label(self.tbmg.packet_scroll.interior, text=str(f))
                    label.grid(row=rownum, column=1)
                    entry = Entry(self.tbmg.packet_scroll.interior, width=30)
                    entry.grid(row=rownum, column=2)
                    toggle = Button(self.tbmg.packet_scroll.interior, text='F', bg=self.red)
                    toggle.configure(command=lambda button=toggle : updateToggleButton(button))
                    toggle.grid(row=rownum, column=3)
                    try:
                        entry.insert(0, str(l.fields[f]).encode('utf8'))
                    except:
                        # print('FOUND ODD ENCODING:', chardet.detect(str(l.fields[f])))
                        entry.insert(0, str(l.fields[f]).encode('hex'))
                    self.gui_layers[l.name].append((layer, label, entry, toggle))
                    rownum += 1
            except Exception, e:
                print('print disect yes intercpet error', e)
                break


if __name__ == '__main__':
    print ('running me')
    p = IP(dst="8.8.8.8")/ICMP()
    f = FuzzPacket(p, packet_feilds_=[('IP', 'ttl')])
    f.startAFLFuzz()
    #f.startScapyFuzz()