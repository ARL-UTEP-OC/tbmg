"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

from Tkinter import *
from scapy.all import *
import os
from multiprocessing import Pipe
import time
from GuiUtils import VerticalScrolledFrame
import interceptor
from StringIO import StringIO
import sys
import tkFileDialog
from ScrolledText import ScrolledText
import datetime
import tkMessageBox
import tempfile


class ScapyBridge(object):
    
    def __init__(self, tbmg_, is_outgoing_=False):
        # output catches outgoing packets, input from other machines, and forward for mitm
        #self.iptablesr = "iptables -A OUTPUT -j NFQUEUE --queue-num 0; iptables -A FORWARD -j NFQUEUE --queue-num 0; iptables -A INPUT -j NFQUEUE --queue-num 0"
        #self.iptablesr = ""#""iptables -t nat -A PREROUTING -j NFQUEUE --queue-num 2"
        #self.iptablesr = 'iptables -I INPUT 1 -j NFQUEUE --queue-balance 0:2'
        
        self.is_outgoing = is_outgoing_
        self.tbmg = tbmg_
        if self.is_outgoing:
            self.gui_layersPCAP = {}  # only in sender!!!
        self.iptablesr = ''
        self.iptablesr_nat = ''
        self.defineIptableRules()
        self.q = None
        self.status = False
        self.cleanup = False
        self.filter = None
        self.parent_conn, self.child_conn = Pipe()
        self.pcapfile = ''
        self.intercepting = False
        self.gui_layers = {}  # gui_layers['IP'] = [(Label(text=layer),Label(text=feild_name),Entry(text=feild_value)),(L,E),...]
        self.current_pack = None
        self.intercepter = None #interceptor.Interceptor()
        self.packet_queue = [] #[x] = (prio#, scapy_packet)
        self.display_lock = Lock()
        self.queue_lock = Lock()
        self.nointerceptLock = Lock()
        self.clear_queue_lock = Lock()
        self.pack_num_counter=1
        self.skip_to_pack_num=0#use me to skip ahead
        self.pack_view_packs =[]
        self.ether_pass = []
        self.save_stdout = sys.stdout
        self.arp_stop = False
        self.arp_sniff_thread = Thread(target=self.arpSniff)
        self.arp_sniff_thread.setDaemon(True)
        self.proto_colors = {}
        self.loadSettings()

    
    #delete chksum and len fields of each layer and have show2 fix it xD
    def fixPacket(self, p):
        index = 0
        while 1:
            try:
                p[index]
                try:
                    del p[index].chksum
                except:
                    pass
                try:
                    del p[index].len
                except:
                    pass
                index = index+1
            except:
                break
        p.show2()
        return p
    
    def defineIptableRules(self):
        if self.is_outgoing:
            self.iptablesr = 'iptables -I OUTPUT 1 -j NFQUEUE --queue-balance 0:19; iptables -I FORWARD 1 -j NFQUEUE --queue-balance 0:19'
            self.iptablesr_nat = 'iptables -I OUTPUT 1 -j NFQUEUE --queue-balance 0:19 -t nat; iptables -I FORWARD 1 -j NFQUEUE --queue-balance 0:19 -t nat'
        else:
            self.iptablesr = 'iptables -I INPUT 1 -j NFQUEUE --queue-balance 20:39'
            self.iptablesr_nat = 'iptables -I INPUT 1 -j NFQUEUE --queue-balance 20:39 -t nat'
        if self.tbmg.iptables_interface:
            self.iptablesr = self.iptablesr + ' -i ' + self.tbmg.iptables_interface
            self.iptablesr_nat = self.iptablesr_nat + ' -i ' + self.tbmg.iptables_interface

        print 'refreshed rules to:',self.iptablesr

    def loadSettings(self):
        self.proto_colors ={}
        color_config = open('/root/tbmg/scapyProxy/color_config.csv', 'r')
        for line in color_config.readlines():
            try:
                proto, color = line.strip().split(',')
                self.proto_colors[proto.strip()] = color.strip()
            except:
                print 'bad color config line'
        color_config.close()
    
    #only run in one scapy_bridge instance (if self.is_outgoing)
    def loadPCAP(self):
        def popUP(i):
            print 'CLICKED PACKET:',str(i)
            pkt = self.pack_view_packs[i]
            popup = Toplevel()
            popup.title = pkt.summary()
            pack_text = self._packet_disect_nointercept(pkt)
            sys.stdout = self.save_stdout
            replace_incoming = Button(popup, text='Replace Incoming',command=lambda pack=pkt: self.tbmg.scapybridgeR._packet_disect_intercept(pack,True))
            replace_outgoing = Button(popup, text='Replace Outgoing',command=lambda pack=pkt: self.tbmg.scapybridgeS._packet_disect_intercept(pack,True))
            manual = Button(popup, text='Manual Send', command=lambda pack=pkt.copy(): self.tbmg.scapybridgeS._packet_disect_intercept(pack,3))
            manual.grid(row=6, column=0)
            msg = ScrolledText(popup)
            msg.grid(row=0,column=0,columnspan=3, sticky='NEWS')
            manual.grid(row=1, column=0, sticky='NEWS')
            replace_incoming.grid(row=1, column=1, sticky='NEWS')
            replace_outgoing.grid(row=1, column=2, sticky='NEWS')
            msg.insert(END, pack_text)
        self.pack_view_packs = []
        name = tkFileDialog.askopenfilename(initialdir="/root/tbmg/sampleConfigs/captures",
                                            filetypes=[("pcap", "*.pcap")])
        if not name:
            return
        for button in self.tbmg.pack_view.interior.grid_slaves():
            button.destroy()
        #sizelabel = Label(self.tbmg.pack_view.interior, text='', width=80)
        #sizelabel.grid(row=0, column=0, columnspan=2)
        i = 0
        self.pack_view_packs=[]
        packets = rdpcap(name)
        for p in packets:
            if i>1200:
                break
            summary = p.summary()
            if len(summary) > 140:
                summary = summary[:len(summary)/2]+"\n"+summary[len(summary)/2:]
            print (i)
            b = Button(self.tbmg.pack_view.interior, text=str(i)+":"+summary, width=80, command=lambda j=i: popUP(j))
            if p.lastlayer().name in self.proto_colors:
                b.config(bg=(self.proto_colors[p.lastlayer().name]))
            else:
                #print 'counld not color:',p.lastlayer().name
                temp_pack = p.copy()
                while 1:
                    try:
                        if temp_pack.lastlayer().name in self.proto_colors:
                            b.config(bg=(self.proto_colors[temp_pack.lastlayer().name]))
                            break
                        del(temp_pack[temp_pack.lastlayer().name])
                    except:
                        break
            b.grid(row=i, column=0)
            self.pack_view_packs.append(p)
            i = i+1
        
    def arpHelper(self,pkt):
        im_the_dst = bool(str(pkt['ARP'].hwdst) in self.tbmg.macs)
        if not self.is_outgoing:
            if im_the_dst:
                t = Thread(target=self.callback, args=(raw(pkt), None, None, None, raw(pkt)))
                t.setDaemon(True)
                t.start()
        elif not im_the_dst:
            t = Thread(target=self.callback, args=(raw(pkt), None, None, None, raw(pkt)))
            t.setDaemon(True)
            t.start()
    
    def arpSniff(self):
        #TODO seperate in/out arps
        a = sniff(prn=self.arpHelper, filter='arp',stop_filter=lambda x: self.arp_stop is True)
        print('stopped apr sniff')
    
    def sendDrop(self):
        if self.tbmg.traffic_tab.tab(self.tbmg.traffic_tab.select(), 'text') == 'PCAP':
            self.clearRaw()
            self.clearDisect()
            return
        if self.intercepting:
            self.parent_conn.send('drop')
    
    def sendRawUpdate(self):
        if self.tbmg.traffic_tab.tab(self.tbmg.traffic_tab.select(), 'text') == 'PCAP':
            text = str(self.tbmg.rawtextP.get('0.0', END)).strip()
            self.current_packPCAP = Ether(text.decode('hex'))
            print 'going to send raw...'
            self.current_packPCAP = self.fixPacket(self.current_packPCAP)
            if self.tbmg.output_interface:
                sendp(self.current_packPCAP, iface=self.tbmg.output_interface)
            else:
                sendp(self.current_packPCAP)
            print 'send packet'
            return
        if self.intercepting:
            if self.is_outgoing:
                text = str(self.tbmg.rawtextS.get('0.0', END)).strip()
            else:
                text = str(self.tbmg.rawtextR.get('0.0', END)).strip()
            print 'updating to:', text
            if self.status:
                self.parent_conn.send('raw')
                self.parent_conn.send(text)
            else:
                print 'going to send raw...'
                self.current_packPCAP = self.fixPacket(self.current_packPCAP)
                if self.tbmg.output_interface:
                    sendp(self.current_packPCAP, iface=self.tbmg.output_interface)
                else:
                    sendp(self.current_pack)
                print 'send packet'
    
    #read dissect GUI and update current packet
    def sendDisectUpdate(self):
        print 'sendDisectUpdate'
        if not self.intercepting and not self.tbmg.traffic_tab.tab(self.tbmg.traffic_tab.select(), 'text') == 'PCAP':
            return
        print 'sendDisectUpdate1'
        #skip if no GUI
        if self.is_outgoing:
            if self.tbmg.traffic_tab.tab(self.tbmg.traffic_tab.select(), 'text') == 'PCAP':
                if not self.gui_layersPCAP or len(self.tbmg.disectlistP.interior.grid_slaves()) < 2:
                    return
            elif not self.gui_layers or len(self.tbmg.disectlistS.interior.grid_slaves()) < 2:
                return
        else:
            if not self.gui_layers or len(self.tbmg.disectlistR.interior.grid_slaves()) < 2:
                return
        print 'sendDisectUpdate2'
        #update packet based on GUI
        #self.current_pack.show2()
        if self.tbmg.traffic_tab.tab(self.tbmg.traffic_tab.select(), 'text') == 'PCAP':
            gui_l = self.gui_layersPCAP
            local_current_pack = self.current_packPCAP
        else:
            gui_l = self.gui_layers
            local_current_pack = self.current_pack
        for layer in gui_l:
            if layer and layer in local_current_pack:
                for pair in gui_l[layer]:
                    type1 = type(getattr(local_current_pack[layer], pair[1].cget('text')))  # correct type for feild
                    type2 = None
                    value = None
                    try:
                        value = str(int(pair[2].get())).strip()
                    except:
                        value = str(pair[2].get())
                        try:
                            value = '"' + value.encode('utf8') + '"'
                        except:  # should only happen on custom input
                            print 'oddball:', value
                            if type1 == int:
                                value = int(value.encode('hex'), 16)
                            else:
                                value = '"' + value.decode('hex') + '"'  # assuming unicode
                    # TODO add protocol exceptions here! vvv
                    try:
                        if type(value) == str and type1 == str:
                            hex_value = value
                            if hex_value[0] == '"':
                                hex_value=hex_value[1:-1]
                            if int(hex_value, 16):
                                ok = True
                                for letter in hex_value:
                                    num = int(letter.encode('hex'))
                                    if not((num >=  int('a'.encode('hex')) and num <=  int('f'.encode('hex'))) or
                                           (num >= int('A'.encode('hex')) and num <= int('F'.encode('hex'))) or
                                           (num >= int('0'.encode('hex')) and num <= int('9'.encode('hex')))):
                                        ok = False
                                        #print letter + ' - is not ok with:', num
                                        break
                                    else:
                                        pass
                                        #print letter+' - is ok with:',num
                                if ok:
                                    #value = '"' + value[1:-1].decode('hex') + '"'
                                    print 'should be ok HEX:',hex_value
                                    hex_value = hex_value.decode('hex')
                                    local_current_pack[layer].fields[pair[1].cget('text')] = hex_value
                                    print('found HEX', hex_value, 'now has:',getattr(local_current_pack[layer], pair[1].cget('text')), 'at:',pair[1].cget('text'), ' in:',layer)
                                    continue
                    except Exception:
                        pass
                        # print value,'not HEX',e
                    if '['in value and ']'in value:#type(value) == str and len(value) >= 4 and value[1] == '[' and value[-2] == ']' and type1 == type([]):
                        #print 'found array type:'+value
                        value = value[1:-1]
                    elif value == '"None"':
                        if type1 == type(None) or not getattr(local_current_pack[layer], pair[1].cget('text')):
                            continue
                        if type1 == int:
                            value = '0'
                        else:
                            print 'set NONE 1:',getattr(local_current_pack[layer], pair[1].cget('text'))
                            value = 'None'
                    elif value == '""':
                        if not getattr(local_current_pack[layer], pair[1].cget('text')):
                            continue
                        try:
                            if not int(str(getattr(local_current_pack[layer], pair[1].cget('text'))).encode('hex')):
                                continue
                        except:
                            pass
                        print 'set NONE 2:',getattr(local_current_pack[layer], pair[1].cget('text'))
                        value = 'None'
                    if layer == 'Raw' and pair[1].cget('text') == 'load':  # ping 8.8.4.4
                        try:
                            #if not local_current_pack[layer].load == value[1:-1].decode('hex'):
                            #    print("FOUND CHANGE in RAW!!!", value, value.encode('hex'))
                            #    print(local_current_pack['Raw'].load, local_current_pack['Raw'].load.encode('hex'))
                            #    print('------------------')
                            #    continue  # use default val
                            local_current_pack['Raw'].load = value[1:-1]#.decode('hex')
                            continue
                        except:
                            pass #non hex decodable
                    #('checking if equal:', 'local_current_pack[\'DNS\'].qd == "\ndiscordapp\x03com"')
                    #local_current_pack['DNS'].qd == "
                    # TODO add protocol exceptions here! ^^^
                    #set value to packet
                    #execute = "local_current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
                    #print('setting:', execute)
                    try:
                        if getattr(local_current_pack[layer], pair[1].cget('text')) != eval(value):
                            execute = "local_current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
                            #print('setting:', execute)
                            #print 'oldval->',getattr(local_current_pack[layer],pair[1].cget('text')),type(getattr(local_current_pack[layer],pair[1].cget('text')))
                            setattr(local_current_pack[layer], pair[1].cget('text'), eval(value))
                            print 'newval->',getattr(local_current_pack[layer],pair[1].cget('text')),type(getattr(local_current_pack[layer],pair[1].cget('text'))), '@'+pair[1].cget('text'),'was:',type1
                    except Exception, e:
                        print 'setattr err:',e,'->',"local_current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
        
        #local_current_pack.show()
        #local_current_pack.show2()
        print 'making raw from disect'
        r = raw(local_current_pack)
        print('producing from disect:', r.encode('hex'))
        if self.status and self.intercepting:
            self.current_pack = local_current_pack
            self.parent_conn.send(r)
        else:
            print 'going to send...'
            self.current_packPCAP = self.fixPacket(local_current_pack)
            if self.tbmg.output_interface:
                sendp(self.current_packPCAP, iface=self.tbmg.output_interface)
            else:
                sendp(self.current_packPCAP)
            print 'send packet'
        if self.tbmg.traffic_tab.tab(self.tbmg.traffic_tab.select(), 'text') == 'PCAP':
            self.gui_layersPCAP = None
        else:
            self.gui_layers = None
        self.clearDisect()
        self.clearRaw()
    
    def clearDisect(self):
        if self.is_outgoing:
            in_pcap_tab = self.tbmg.traffic_tab.tab(self.tbmg.traffic_tab.select(),'text') == 'PCAP'
            if in_pcap_tab:
                for w in self.tbmg.disectlistP.interior.winfo_children():
                    w.destroy()
                return
            for w in self.tbmg.disectlistS.interior.winfo_children():
                w.destroy()
        else:
            for w in self.tbmg.disectlistR.interior.winfo_children():
                w.destroy()
                
    def clearQueue(self):
        self.tbmg.extraInterceptedGUI(False)
        self.tbmg.extraInterceptedGUI(True)
     
    def clearRaw(self):
        if self.is_outgoing:
            if self.tbmg.traffic_tab.tab(self.tbmg.traffic_tab.select(), 'text') == 'PCAP':
                self.tbmg.rawtextP.delete(0.0, END)
            self.tbmg.rawtextS.delete(0.0, END)
        else:
            self.tbmg.rawtextR.delete(0.0, END)
    
    def _packet_disect_intercept(self, pack, overwrite_current_pack=False):
        print 'calling _packet_disect_intercept!!!!!!!!!!!'
        if not overwrite_current_pack == 3 and not self.intercepting:
            tkMessageBox.showinfo('TMBG - Not Intercepting', 'To replace a packet, make sure INTERCEPTING is on.')
            return
        
        self.clearDisect()
        if overwrite_current_pack and not overwrite_current_pack == 3:#used to deal w/ pcap overwrites
            self.current_pack = pack
        rownum = 1
        if overwrite_current_pack == 3:
            self.current_packPCAP = pack
            self.gui_layersPCAP = {}
            self.clearRaw()
            self.tbmg.rawtextP.insert('0.0', str(raw(self.current_packPCAP)).encode('hex'))
            sizelabel = Label(self.tbmg.disectlistP.interior, text='', width=50)
            sizelabel.grid(row=0, column=0, columnspan=5)
            for i in range(10):
                try:
                    l = pack.getlayer(i)
                    if not l:
                        continue
                    self.gui_layersPCAP[l.name] = []
                    layer = Label(self.tbmg.disectlistP.interior, text=l.name)
                    if l.name in self.tbmg.scapybridgeS.proto_colors:
                        #print 'found layer color!',self.tbmg.scapybridgeS.proto_colors[l.name]
                        layer.config(bg=self.tbmg.scapybridgeS.proto_colors[l.name])
                    else:
                        pass
                        #print 'count not color layer:',l.name
                    layer.grid(row=rownum, column=0)
                    rownum += 1
                    if l.name == 'Ethernet' or l.name == 'Ether':
                        label = Label(self.tbmg.disectlistP.interior, text='src')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistP.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].src).encode('utf8'))
                        self.gui_layersPCAP[l.name].append((layer, label, entry))
                        rownum += 1
                
                        label = Label(self.tbmg.disectlistP.interior, text='dst')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistP.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].dst).encode('utf8'))
                        self.gui_layersPCAP[l.name].append((layer, label, entry))
                        rownum += 1
                
                        label = Label(self.tbmg.disectlistP.interior, text='type')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistP.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].type).encode('utf8'))
                        self.gui_layersPCAP[l.name].append((layer, label, entry))
                        rownum += 1
                        continue
            
                    for f in l.fields:
                        label = Label(self.tbmg.disectlistP.interior, text=str(f))
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistP.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        try:
                            entry.insert(0, str(l.fields[f]).encode('utf8'))
                        except:
                            # print('FOUND ODD ENCODING:', chardet.detect(str(l.fields[f])))
                            entry.insert(0, str(l.fields[f]).encode('hex'))
                        self.gui_layersPCAP[l.name].append((layer, label, entry))
                        rownum += 1
                except Exception, e:
                    print 'print disect yes intercpet error', e
                    break
        elif self.is_outgoing:
            self.gui_layers = {}
            if overwrite_current_pack:
                self.clearRaw()
                self.tbmg.rawtextS.insert('0.0', str(raw(self.current_pack)).encode('hex'))
            sizelabel = Label(self.tbmg.disectlistS.interior, text='', width=50)
            sizelabel.grid(row=0, column=0, columnspan=5)
            for i in range(10):
                try:
                    l = pack.getlayer(i)
                    if not l:
                        continue
                    self.gui_layers[l.name] = []
                    
                    layer = Label(self.tbmg.disectlistS.interior, text=l.name)
                    if l.name in self.tbmg.scapybridgeS.proto_colors:
                        #print 'found layer color!', self.tbmg.scapybridgeS.proto_colors[l.name]
                        layer.config(bg=self.tbmg.scapybridgeS.proto_colors[l.name])
                    else:
                        pass
                        #print 'count not color layer:', l.name
                    layer.grid(row=rownum, column=0)
                    rownum += 1
                    if l.name == 'Ethernet' or l.name == 'Ether':
                        label = Label(self.tbmg.disectlistS.interior, text='src')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistS.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].src).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                        
                        label = Label(self.tbmg.disectlistS.interior, text='dst')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistS.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].dst).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                        
                        label = Label(self.tbmg.disectlistS.interior, text='type')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistS.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].type).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                        continue
                        
                    for f in l.fields:
                        label = Label(self.tbmg.disectlistS.interior, text=str(f))
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistS.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        try:
                            entry.insert(0, str(l.fields[f]).encode('utf8'))
                        except:
                            #print('FOUND ODD ENCODING:', chardet.detect(str(l.fields[f])))
                            entry.insert(0, str(l.fields[f]).encode('hex'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                except Exception, e:
                    print 'print disect yes intercpet error', e
                    break
        else:
            self.gui_layers = {}
            if overwrite_current_pack:
                self.clearRaw()
                self.tbmg.rawtextR.insert('0.0', str(raw(self.current_pack)).encode('hex'))
            sizelabel = Label(self.tbmg.disectlistR.interior, text='', width=50)
            sizelabel.grid(row=0, column=0, columnspan=5)
            for i in range(10):
                try:
                    l = pack.getlayer(i)
                    if not l:
                        continue
                    self.gui_layers[l.name] = []
            
                    layer = Label(self.tbmg.disectlistR.interior, text=l.name)
                    if l.name in self.tbmg.scapybridgeS.proto_colors:
                        print 'found layer color!',self.tbmg.scapybridgeS.proto_colors[l.name]
                        layer.config(bg=self.tbmg.scapybridgeS.proto_colors[l.name])
                    else:
                        pass
                        #print 'count not color layer:',l.name
                    layer.grid(row=rownum, column=0)
                    rownum += 1
                    if l.name == 'Ethernet' or l.name == 'Ether':
                        label = Label(self.tbmg.disectlistR.interior, text='src')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistR.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].src).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                
                        label = Label(self.tbmg.disectlistR.interior, text='dst')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistR.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].dst).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                
                        label = Label(self.tbmg.disectlistR.interior, text='type')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistR.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].type).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                        continue
            
                    for f in l.fields:
                        label = Label(self.tbmg.disectlistR.interior, text=str(f))
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistR.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        try:
                            entry.insert(0, str(l.fields[f]).encode('utf8'))
                        except:
                            print('FOUND ODD ENCODING:', f)
                            entry.insert(0, str(l.fields[f]).encode('hex'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                except Exception, e:
                    print 'print disect yes intercpet error', e
                    break
        
        self.tbmg.root.update()
        print 'called Tk.update()!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
        
    def _packet_disect_nointercept(self, pack):
        self.nointerceptLock.acquire()
        try:
            capture = StringIO()
            sys.stdout = capture
            pack.show()
            sys.stdout = self.save_stdout
            self.nointerceptLock.release()
            return capture.getvalue()+'\n----------------------------------\n'
        except:
            sys.stdout = self.save_stdout
            self.nointerceptLock.release()
            return '\n'
    
    def interceptToggle(self):
        self.intercepting = not self.intercepting
        if self.is_outgoing:
            def addnointercptGUI():
                self.tbmg.disecttextS = ScrolledText(self.tbmg.disect_tab_out, height=30, width=60)
                self.tbmg.disecttextS.grid(row=0, column=0, columnspan=5)
                self.tbmg.disecttextS.insert(END, 'DISECT\n---\n')
                
            def addintercptGUI():
                self.tbmg.disectlistS = VerticalScrolledFrame(self.tbmg.disect_tab_out, height=30, width=80)
                self.tbmg.disectlistS.grid(row=0, column=0, columnspan=3)
                self.tbmg.disectLableS = Label(self.tbmg.disectlistS.interior, text='DISECT VIEW\n----\n', width='50')
                self.tbmg.disectLableS.grid(row=0, column=0)

            for item in self.tbmg.disect_tab_out.winfo_children():
                if not isinstance(item, Button):
                    item.destroy()
                
        else:
            #called first
            self.tbmg.restoreIPTables()
            def addnointercptGUI():
                self.tbmg.disecttextR = ScrolledText(self.tbmg.disect_tab_in, height=30, width=60)
                self.tbmg.disecttextR.grid(row=0, column=0, columnspan=3)
                self.tbmg.disecttextR.insert(END, 'DISECT\n---\n')
    
            def addintercptGUI():
                self.tbmg.disectlistR = VerticalScrolledFrame(self.tbmg.disect_tab_in, height=30, width=80)
                self.tbmg.disectlistR.grid(row=0, column=0, columnspan=3)
                self.tbmg.disectLableR = Label(self.tbmg.disectlistR.interior, text='DISECT VIEW\n----\n', width='50')
                self.tbmg.disectLableR.grid(row=0, column=0)
    
            for item in self.tbmg.disect_tab_in.winfo_children():
                if not isinstance(item, Button):
                    item.destroy()
                
        if self.intercepting:
            addintercptGUI()
        else:
            addnointercptGUI()
        
        print 'intercpet is:', (self.intercepting)
        if not self.intercepting:
            print 'IsOutgoing?', self.is_outgoing, ' - locked?:', self.display_lock.locked()
            self.skip_to_pack_num = sys.maxint - 1
            self.parent_conn.send('accept')
            while self.display_lock.locked():
                print 'waiting...'
                #self.display_lock.release()
                time.sleep(.025)
            time.sleep(.3)
            while self.child_conn.poll():
                print 'eating extra...'
                self.child_conn.recv()
            self.skip_to_pack_num = 0
            self.clearRaw()
            try:
                self.clearDisect()
            except:
                pass
        else:
            self.clearRaw()
        if self.is_outgoing and self.status:
            #called last
            self.tbmg.scapybridgeR.setIPTables()
            self.tbmg.scapybridgeS.setIPTables()
            print 're-proxying table!'
        print 'done toggling.....'

    def setIPTables(self):
        print("Adding iptable rules :", self.iptablesr)
        os.system(self.iptablesr)
        os.system(self.iptablesr_nat)

    def myTCPdump(self):
        os.system('tcpdump -c 500 -w ' + self.pcapfile)

    def proxyToggle(self):
        #print(not self.status)
        self.status = not self.status
        self.cleanup = False
        if self.status:
            try:
                self.setIPTables()
                try:
                    print 'about to start proxy'
                    self.arp_stop = False
                    self.arp_sniff_thread = Thread(target=self.arpSniff)
                    self.arp_sniff_thread.setDaemon(True)
                    self.arp_sniff_thread.start()
                    if self.pcapfile:
                        self.tcpdump = Thread(target=self.myTCPdump)
                        self.tcpdump.setDaemon(True)
                        self.tcpdump.start()

                    if not self.intercepter:
                        self.intercepter = interceptor.Interceptor()
                        if self.is_outgoing:
                            self.intercepter.start(self.callback, queue_ids=range(20))
                        else:
                            self.intercepter.start(self.callback, queue_ids=range(20, 40))
                    print ('moving after proxy start')
                except Exception, e:
                    print 'COUNDT START PROXY', e
                    print("Restoring iptables.")
                    # This flushes everything, you might wanna be careful
                    # may want a way to restore tables after
                    if os.path.isfile(self.tbmg.iptables_save):
                        os.system('iptables-restore ' + self.tbmg.iptables_save)
                        os.remove(self.tbmg.iptables_save)
            except Exception, e:
                print 'start proxy err', e
        else:
            try:
                #TODO change to accept the exact amount of packs
                self.arp_stop = True
                print 'mass accept packs'
                #clean gui/packs
                if self.intercepting:
                    self.skip_to_pack_num = sys.maxint - 1
                    #self.parent_conn.send('accept')
                    
                    while self.display_lock.locked():
                        self.parent_conn.send('accept')
                        print 'waiting...'
                        # self.display_lock.release()
                        time.sleep(.025)
                        
                    time.sleep(.3)
                    while self.child_conn.poll():
                        print 'eating extra...'
                        self.child_conn.recv()
                    self.skip_to_pack_num = 0
                    self.clearRaw()
                    self.clearDisect()
                #os.system('iptables -F')
                #os.system('iptables -X')
                #print 'stoping proxy'
                #self.intercepter.stop()
                
            except Exception, e:
                print 'proxy err:',e
                pass
            self.cleanup = 'Ready'
            
    def hexToPacket(self, hex):
        try:
            print 'org hex:',hex
            hex = " ".join(hex[i:i+2] for i in range(0, len(hex), 2))
            hex = "00000 " + hex
            #print ('want to use hex:', hex)
            txt_fd, filename_txt = tempfile.mkstemp('.txt')
            temp_txt = os.fdopen(txt_fd,'w')
            temp_txt.write(hex)
            temp_txt.close()
            temp_pcap,filename_pcap = tempfile.mkstemp('.pcap')
            command = "text2pcap "+filename_txt+" "+filename_pcap+" "
            #print ('using:', filename_txt, ' and ', filename_pcap, ' - doing: ', command)
            os.system(command)
            os.remove(filename_txt)
            packet= rdpcap(filename_pcap)[0]
            os.remove(filename_pcap)
            return packet
        except:
            return Ether()
        

    # ran from seperate process
    def callback(self, ll_data, ll_proto_id, data, ctx, arp=None):
        # Here is where the magic happens.
        def skipAhead(dst_num):
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            self.skip_to_pack_num = dst_num
            self.parent_conn.send('accept')
        try:
            i_have_lock = False
            if not self.status:
                print 'I should not be on...'
                return data, interceptor.NF_ACCEPT
            num = self.pack_num_counter
            self.pack_num_counter +=1 # may need to make this thread safe
            #TODO handle protos other than ether and IP T-T eg CookedLinux and maybe IPv6
            hex_text = ''
            if arp:
                packet = Ether(arp)
                '''
            else:#if ll_data:
                hex_text = str(ll_data).encode('hex')
                if data:
                    hex_text = hex_text + str(data).encode('hex')
                print 'adding ether'
                packet = Ether()/IP(hex_text.decode('hex'))
                packet.show2()
                hex_text = raw(packet)
                print 'data   :', ll_data, data
                print 'encoded:', hex_text
                packet = self.hexToPacket(hex_text)
                print'done dissect:'
                packet.show2()
                print'would have got:'
                (Ether(ll_data) / IP(data)).show2()'''
            else:
                #print 'no ll_data'
                if data:
                    packet = Ether(ll_data) / IP(data)
                else:
                    packet = Ether(ll_data)
            org = packet.copy()
            org.show2()
            packet.show2()
            print (raw(packet).encode('hex'))
            #print '~~~~~~~~~~~~~~~~~'
            #print 'or maybe....'
            #Ether(data).show2()
            print'======================='
            
            #if data:
                #print ('want to use hex:', str(ll_data).encode('hex') + str(data).encode('hex'))
                #packet = self.hexToPacket(str(ll_data).encode('hex') + str(data).encode('hex'))
                #packet = Ether(ll_data) / IP(data)
                #org = Ether(ll_data) / IP(data)
            #else:
                #print ('want to use hex:', str(ll_data).encode('hex'))
            
            #print 'rawCall:', raw(Raw(ll_data)).encode('hex'), raw(Raw(data)).encode('hex')
            
            #    packet = Ether(ll_data)
            #    org =Ether(ll_data)
            
            #skip what I send
            if packet in self.ether_pass:#arp should not catch here...
                print 'FOUND SENT ETH CHANGE PACKET - ACCEPTING'
                #packet.show()
                self.ether_pass.remove(packet)
                return data, interceptor.NF_ACCEPT
            if self.is_outgoing:
                try:
                    if packet in self.tbmg.fuzz_packet.accept_me:
                        print 'FOUND OUTGOING FUZZ'
                        self.tbmg.fuzz_packet.accept_me.remove(packet)
                        return data,interceptor.NF_ACCEPT#TODO handle arp change
                except:
                    pass
            
            #check filter
            dofilter = False  # show package in gui when = True
            if self.filter:
                try:
                    dofilter = bool(sniff(offline=packet, filter=self.filter))
                    if not dofilter:
                        if data:
                            return data, interceptor.NF_ACCEPT
                        elif self.intercepting:
                            #sendp(packet)
                            return
                except Exception, e:
                    print 'Filter err:', self.filter, e
                    if data:
                        return data, interceptor.NF_ACCEPT
                    elif self.intercepting:
                        #sendp(packet)
                        return
                    
            #Perform hooks
            for hook in self.tbmg.active_hook_profile.hook_manager:
                if hook[5]: #is active
                    try:
                        old_packet = packet.copy()
                        packet, accept_or_drop = hook[0](packet).run()
                        # fix chksum and len
                        print 'old pack:'
                        old_packet.show()
                        print 'new pack:'
                        packet = self.fixPacket(packet)
                        print '-----------------'
                        if accept_or_drop == interceptor.NF_DROP:
                            print 'hook is droping the packet'
                            return data, interceptor.NF_DROP
                    except:
                        print 'HOOK FAILED'

            # list packet arival - add to queue
            self.queue_lock.acquire()
            i_have_lock = 1
            print("Got a packet " + str(num))  # +":", packet.summary())
            parent = None
            test_frame = None
            button = None
            timelabel = None
            if self.intercepting:
                id = time.time()  # self.getID()
                parent = self.tbmg.netqueueframeS if self.is_outgoing else self.tbmg.netqueueframeR
                if not self.status:
                    print 'Trying to make invalid GUI stuff', self.status
                    self.queue_lock.release()
                    return data, interceptor.NF_ACCEPT
                test_frame = Frame(parent.interior)
                summary = packet.summary()
                if len(summary) > 140:
                    summary = summary[:len(summary)/2] + "\n" + summary[len(summary)/2:]
                button = Button(test_frame, text=str(num) + ":" + summary,
                                width="80", command=lambda: skipAhead(num))#,yscrollcommand=parent.vscrollbar.set)
                #handle proto color TODO, put in method packetToColor(packet)
                if packet.lastlayer().name in self.proto_colors:
                    button.config(bg=(self.proto_colors[packet.lastlayer().name]))
                else:
                    #print 'counld not color:',packet.lastlayer().name
                    temp_pack = packet.copy()
                    while 1:
                        try:
                            if temp_pack.lastlayer().name in self.proto_colors:
                                button.config(bg=(self.proto_colors[temp_pack.lastlayer().name]))
                                break
                            del(temp_pack[temp_pack.lastlayer().name])
                        except:
                            break
                    
                timelabel = Label(test_frame, text=(datetime.datetime.now().strftime("%H:%M:%S.%f") + '; 0'))
                button.grid(row=0, column=0)
                timelabel.grid(row=0, column=1)

                test_frame.pack()
                self.tbmg.timers.append(timelabel)
            self.queue_lock.release()
            i_have_lock = 0

            # lock - one at a time get to render,
            was_intercepting = self.intercepting
            print 'want lock'
            self.display_lock.acquire()
            i_have_lock = 2
            print 'got lock for ',str(num)
            #check status
            if not self.status:
                print 'I should not be on...', num
                try:
                    if timelabel:
                        print 'removing timelabel'
                        self.tbmg.timers.remove(timelabel)
                except Exception as e:
                    print 'I should not be on err1', num, e
                try:
                    if self.cleanup and parent:
                        print 'calling to clean queue'
                        self.clearQueue()
                except Exception as e:
                    print 'I should not be on err2',num,e
                self.display_lock.release()
                if data:
                    return data, interceptor.NF_ACCEPT
                elif self.intercepting:
                    #sendp(packet)
                    pass
                return
            #if self.skip_to_pack_num:
            if num < self.skip_to_pack_num:
                print 'skipping! im at', str(num)
                if not (was_intercepting and not self.intercepting) and test_frame:
                    print 'normal skip'
                    test_frame.destroy()
                self.tbmg.timers.remove(timelabel)
                print 'releasing from skip....'
                self.display_lock.release()
                if data:
                    return data, interceptor.NF_ACCEPT
                else:
                    #sendp(packet)
                    return
            elif num == self.skip_to_pack_num:
                print 'hit num.im at',str(num)
                self.skip_to_pack_num=0
            
            self.current_pack = packet.copy()
            self.current_pack.show2()
            if self.intercepting:
                print 'intercepting'
                if self.filter and not dofilter:
                    print 'intercept, but not in filter'
                    if self.pcapfile:
                        wrpcap(self.pcapfile, org, append=True)
                        wrpcap(self.pcapfile[:-5] + '_mod.pcap', org, append=True)
                    self.display_lock.release()
                    if data:
                        return data, interceptor.NF_ACCEPT
                    elif self.intercepting:
                        #sendp(packet)
                        return
                
                #display packet
                self.clearDisect()
                self.clearRaw()
                self._packet_disect_intercept(self.current_pack)
                if self.is_outgoing:
                    self.tbmg.rawtextS.insert('0.0', str(raw(self.current_pack)).encode('hex'))
                else:
                    self.tbmg.rawtextR.insert('0.0', str(raw(self.current_pack)).encode('hex'))
                
                #recive data from GUI
                #recive data from GUI
                recv = self.child_conn.recv()
                print 'parent called me:', num, recv
                if recv == 'drop':
                    print 'DROPING'
                    self.tbmg.timers.remove(timelabel)
                    test_frame.destroy()
                    self.display_lock.release()
                    #TODO efficently delete self from packet queue
                    if data:
                        return data, interceptor.NF_DROP
                elif recv == 'accept':
                    print "ACCEPTING", str(num)
                    try:
                        self.tbmg.timers.remove(timelabel)
                    except:
                        print 'could not remove timelabel'
                    if not(was_intercepting and not self.intercepting) and self.status:#if normal skip/accept
                        print 'destorying frame'
                        test_frame.destroy()
                    #TODO add to pcap
                    if self.pcapfile:
                        wrpcap(self.pcapfile, org, append=True)
                        wrpcap(self.pcapfile[:-5] + '_mod.pcap', org, append=True)
                    print 'accept going to release'
                    self.display_lock.release()
                    print 'accept released'
                    if data:
                        return data, interceptor.NF_ACCEPT
                    elif self.intercepting:
                        #sendp(packet) #manual send arp?
                        return
                elif recv == 'raw':
                    recv = str(self.child_conn.recv())
                    #TODO make more definite way...
                    #self.current_pack = self.hexToPacket(recv)
                    if data:
                        self.current_pack = Ether(recv[:recv.index('450000')].decode('hex'))/ IP(recv[recv.index('450000'):].decode('hex'))
                    else:
                        self.current_pack = Ether(recv)#TODO check if arp gets this
                elif recv == 'disect':#already been modded
                    pass
                
                # fix chksum and len
                self.current_packPCAP = self.fixPacket(self.current_packPCAP)
                self.clearDisect()
                self.clearRaw()
                #handle updated packet
                if self.pcapfile:
                    wrpcap(self.pcapfile, org, append=True)
                    wrpcap(self.pcapfile[:-5] + '_mod.pcap', self.current_pack, append=True)
                print 'sending updated....',raw(self.current_pack)
                print 'rather than........',data
                test_frame.destroy()
                self.tbmg.timers.remove(timelabel)
                
                #if eth layer changed, NF_DROP and use scapy to send self.current_pack
                if org['Ether'] != self.current_pack['Ether']:
                    if data:
                        self.ether_pass.append(self.current_pack)
                        if self.tbmg.output_interface:
                            sendp(self.current_packPCAP, iface=self.tbmg.output_interface)
                        else:
                            sendp(self.current_pack)
                        test_frame.destroy()
                        self.display_lock.release()
                        return raw(self.current_pack), interceptor.NF_DROP
                    elif self.intercepting:
                        if self.tbmg.output_interface:
                            sendp(self.current_packPCAP, iface=self.tbmg.output_interface)
                        else:
                            sendp(self.current_pack)
                        self.display_lock.release()
                        return
                # TODO efficently delte self from packet queue
                if data:
                    self.display_lock.release()
                    return raw(self.current_pack['IP']), interceptor.NF_ACCEPT
                elif self.intercepting:
                    if self.tbmg.output_interface:
                        sendp(self.current_packPCAP, iface=self.tbmg.output_interface)
                    else:
                        sendp(self.current_pack)
                    self.display_lock.release()
                    return
            else:
                print 'not intercpeting..'
                try:
                    test_frame.destroy()
                    self.tbmg.timers.remove(timelabel)
                except:
                    pass
                if self.is_outgoing:
                    self.tbmg.disecttextS.insert('3.0', self._packet_disect_nointercept(self.current_pack))
                    sys.stdout = self.save_stdout
                    self.tbmg.rawtextS.insert('0.0', '\n- ' + str(raw(self.current_pack)).encode('hex'))
                else:
                    self.tbmg.disecttextR.insert('3.0', self._packet_disect_nointercept(self.current_pack))
                    sys.stdout = self.save_stdout
                    self.tbmg.rawtextR.insert('0.0', '\n- ' + str(raw(self.current_pack)).encode('hex'))
                if self.pcapfile:
                    wrpcap(self.pcapfile, self.current_pack, append=True)
                    wrpcap(self.pcapfile[:-5] + '_mod.pcap', self.current_pack, append=True)
                self.display_lock.release()
                if data:
                    return raw(self.current_pack['IP']), interceptor.NF_ACCEPT
                else:
                    return
        except Exception as e:
            print 'ERRRRRRRRRR!!!!',e
            try:
                print 'releasing lock'
                if i_have_lock == 2:
                    self.display_lock.release()
                if i_have_lock == 1:
                    self.queue_lock.release()
            except:
                pass
        return data,interceptor.NF_ACCEPT
