"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

from Tkinter import *
from scapy.all import *
import os
from multiprocessing import Pipe
import time
from scapyProxy.GuiUtils import VerticalScrolledFrame
import interceptor
from StringIO import StringIO
import sys
import tkFileDialog
from ScrolledText import ScrolledText
import datetime
import tkMessageBox


class ScapyBridge(object):
    
    def __init__(self, tbmg_, is_outgoing_=False):
        # output catches outgoing packets, input from other machines, and forward for mitm
        #self.iptablesr = "iptables -A OUTPUT -j NFQUEUE --queue-num 0; iptables -A FORWARD -j NFQUEUE --queue-num 0; iptables -A INPUT -j NFQUEUE --queue-num 0"
        #self.iptablesr = ""#""iptables -t nat -A PREROUTING -j NFQUEUE --queue-num 2"
        #self.iptablesr = 'iptables -I INPUT 1 -j NFQUEUE --queue-balance 0:2'
        
        self.is_outgoing = is_outgoing_
        self.iptablesr = ''
        if self.is_outgoing:
            self.iptablesr = 'iptables -I OUTPUT 1 -j NFQUEUE --queue-balance 0:19; iptables -I FORWARD 1 -j NFQUEUE --queue-balance 0:19'
            self.gui_layersPCAP = {}  # only in sender!!!
        else:
            self.iptablesr = 'iptables -I INPUT 1 -j NFQUEUE --queue-balance 20:39'
        
        self.tbmg = tbmg_
        self.q = None
        self.status = False
        self.filter = None
        self.parent_conn, self.child_conn = Pipe()
        self.pcapfile = ''
        self.intercepting = False
        self.gui_layers = {}  # gui_layers['IP'] = [(Label(text=layer),Label(text=feild_name),Entry(text=feild_value)),(L,E),...]
        self.current_pack = None
        self.intercepter = None #interceptor.Interceptor()
        self.packet_queue = [] #[x] = (prio#, scapy_packet)
        self.display_lock = Lock()
        self.pack_num_counter=1
        self.skip_to_pack_num=0#use me to skip ahead
        self.pack_view_packs =[]
        self.ether_pass = []
        self.save_stdout = sys.stdout
        self.arp_stop = False
        self.arp_sniff_thread = Thread(target=self.arpSniff)
        self.arp_sniff_thread.setDaemon(True)
        self.loadSettings()
        
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
    
    #only run in one scapy_bridge instance
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
            manual = Button(popup, text='Manual Send', command=lambda pack=pkt: self.tbmg.scapybridgeS._packet_disect_intercept(pack,3))
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
        packets = rdpcap(name)
        for p in packets:
            summary = p.summary()
            if len(summary) > 140:
                summary = summary[:len(summary)/2]+"\n"+summary[len(summary)/2:]
            #print (i, p.summary())
            b = Button(self.tbmg.pack_view.interior, text=summary, width=80, command=lambda j=i: popUP(j))
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
                t = Thread(target=self.callback, args=(raw(pkt),None,None,None))
                t.setDaemon(True)
                t.start()
        elif not im_the_dst:
            t = Thread(target=self.callback, args=(raw(pkt), None, None, None))
            t.setDaemon(True)
            t.start()
    
    def arpSniff(self):
        #TODO seperate in/out arps
        a = sniff(prn=self.arpHelper, filter='arp',stop_filter=lambda x:self.arp_stop==True)
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
            print 'going to send...'
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
                print 'going to send...'
                sendp(self.current_pack)
                print 'send packet'
    
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
                    # TODO add protocol exceptions here!
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
                                    print('found HEX', hex_value, 'org had:',getattr(local_current_pack[layer], pair[1].cget('text')), 'at:',pair[1].cget('text'))
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
                            if not local_current_pack[layer].load == value[1:-1].decode('hex'):
                                print("FOUND CHANGE in RAW!!!", value, value.encode('hex'))
                                print(local_current_pack['Raw'].load, local_current_pack['Raw'].load.encode('hex'))
                                print('------------------')
                                continue  # use default val
                            local_current_pack['Raw'].load = value[1:-1].decode('hex')
                            continue
                        except:
                            pass #non hex decodable
                    #('checking if equal:', 'local_current_pack[\'DNS\'].qd == "\ndiscordapp\x03com"')
                    #local_current_pack['DNS'].qd == "
                    # TODO add protocol exceptions here!
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
            sendp(local_current_pack)
            print 'send packet'
        if self.tbmg.traffic_tab.tab(self.tbmg.traffic_tab.select(), 'text') == 'PCAP':
            self.gui_layersPCAP = None
        else:
            self.gui_layers = None
        self.clearDisect()
        self.clearRaw()
    
    def clearDisect(self):
        if self.is_outgoing:
            if self.tbmg.traffic_tab.tab(self.tbmg.traffic_tab.select(),'text') == 'PCAP':
                for w in self.tbmg.disectlistP.interior.grid_slaves():
                    w.destroy()
                return
            for w in self.tbmg.disectlistS.interior.grid_slaves():
                w.destroy()
        else:
            for w in self.tbmg.disectlistR.interior.grid_slaves():
                w.destroy()
    
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
                        print 'found layer color!', self.tbmg.scapybridgeS.proto_colors[l.name]
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
        try:
            capture = StringIO()
            sys.stdout = capture
            pack.show()
            sys.stdout = self.save_stdout
            return capture.getvalue()+'\n----------------------------------\n'
        except:
            sys.stdout = self.save_stdout
            return '\n'
        finally:
            sys.stdout = self.save_stdout
    
    def interceptToggle(self):
        self.intercepting = not self.intercepting
        if self.is_outgoing:
            def addnointercptGUI():
                #self.tbmg.disecttextS = ScrolledText(self.tbmg.page5, height=30, width=60)
                #self.tbmg.disecttextS.grid(row=3, column=1)
                #self.tbmg.disecttextS.insert(END, 'DISECT\n---\n')
                self.tbmg.disecttextS = ScrolledText(self.tbmg.disect_tab_out, height=30, width=60)
                self.tbmg.disecttextS.grid(row=0, column=0, columnspan=5)
                self.tbmg.disecttextS.insert(END, 'DISECT\n---\n')
            def addintercptGUI():
                self.tbmg.disectlistS = VerticalScrolledFrame(self.tbmg.disect_tab_out, height=30, width=80)
                self.tbmg.disectlistS.grid(row=0, column=0, columnspan=3)
                self.tbmg.disectLableS = Label(self.tbmg.disectlistS.interior, text='DISECT VIEW\n----\n')
                self.tbmg.disectLableS.grid(row=0, column=0)
            
            if self.intercepting:
                if self.tbmg.disecttextS:
                    self.tbmg.disecttextS.destroy()
                    self.tbmg.disecttextS = None
                if not (self.tbmg.disectlistS and self.tbmg.disectLableS):
                    addintercptGUI()
            else:
                if self.tbmg.disectlistS or self.tbmg.disectLableS:
                    self.tbmg.disectlistS.destroy()
                    self.tbmg.disectlistS = None
                    self.tbmg.disectLableS.destroy()
                    self.tbmg.disectLableS = None
                if not self.tbmg.disecttextS:
                    addnointercptGUI()
        else:
            def addnointercptGUI():
                self.tbmg.disecttextR = ScrolledText(self.tbmg.disect_tab_in, height=30, width=60)
                self.tbmg.disecttextR.grid(row=0, column=0, columnspan=3)
                self.tbmg.disecttextR.insert(END, 'DISECT\n---\n')
    
            def addintercptGUI():
                self.tbmg.disectlistR = VerticalScrolledFrame(self.tbmg.disect_tab_in, height=30, width=80)
                self.tbmg.disectlistR.grid(row=0, column=0, columnspan=3)
                self.tbmg.disectLableR = Label(self.tbmg.disectlistR.interior, text='DISECT VIEW\n----\n')
                self.tbmg.disectLableR.grid(row=0, column=0)
    
            if self.intercepting:
                if self.tbmg.disecttextR:
                    self.tbmg.disecttextR.destroy()
                    self.tbmg.disecttextR = None
                if not (self.tbmg.disectlistR and self.tbmg.disectLableR):
                    addintercptGUI()
            else:
                if self.tbmg.disectlistR or self.tbmg.disectLableR:
                    self.tbmg.disectlistR.destroy()
                    self.tbmg.disectlistR = None
                    self.tbmg.disectLableR.destroy()
                    self.tbmg.disectLableR = None
                if not self.tbmg.disecttextR:
                    addnointercptGUI()
        print 'intercpet is now', self.intercepting
        if not self.intercepting:
            self.parent_conn.send('accept')
            self.clearRaw()
            try:
                self.clearDisect()
            except:
                pass
    
    def proxyToggle(self):
        #print(not self.status)
        self.status = not self.status
        if self.status:
            try:
                print("Adding iptable rules :",self.iptablesr)
                if not os.path.isfile(self.tbmg.iptables_save):
                    os.system('iptables-save > '+self.tbmg.iptables_save)
                os.system(self.iptablesr)
                try:
                    print 'about to start proxy'
                    self.arp_stop = False
                    self.arp_sniff_thread = Thread(target=self.arpSniff)
                    self.arp_sniff_thread.setDaemon(True)
                    self.arp_sniff_thread.start()
                    if not self.intercepter:
                        self.intercepter = interceptor.Interceptor()
                        if self.is_outgoing:
                            self.intercepter.start(self.callback, queue_ids=range(20))
                        else:
                            self.intercepter.start(self.callback, queue_ids=range(20, 40))
                    print ('moving after proxy start')
                except Exception, e:
                    print 'COUNDT START PROXY',e
                    print("Restoring iptables.")
                    # This flushes everything, you might wanna be careful
                    # may want a way to restore tables after
                    if os.path.isfile(self.tbmg.iptables_save):
                        os.system('iptables-restore '+ self.tbmg.iptables_save)
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
                    for i in range(40):
                        self.parent_conn.send('accept')
                    time.sleep(.3)
                    while self.child_conn.poll():
                        self.child_conn.recv()
                    self.clearRaw()
                    self.clearDisect()
                #stop proxy
                print('flushing...')
                os.system('iptables -F')
                os.system('iptables -X')
                print 'stoping proxy'
                #self.intercepter.stop()
                
            except Exception, e:
                print 'proxy err:',e
                pass

    # ran from seperate process
    def callback(self, ll_data, ll_proto_id, data, ctx):
        # Here is where the magic happens.
        def skipAhead(dst_num):
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            self.skip_to_pack_num = dst_num
            self.parent_conn.send('accept')
        try:
            if not self.status:
                print 'I should not be on...'
                return data, interceptor.NF_DROP
            num = self.pack_num_counter
            self.pack_num_counter +=1 # may need to make this thread safe
            #TODO handle protos other than ether and IP T-T eg CookedLinux and maybe IPv6
            if data:
                packet = Ether(ll_data) / IP(data)
                org = Ether(ll_data) / IP(data)
            else:
                packet = Ether(ll_data)
                org =Ether(ll_data)
            
            #skip what I send
            if packet in self.ether_pass:#arp should not catch here...
                print 'FOUND SENT ETH CHANGE PACKET - ACCEPTING'
                packet.show()
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
            
            # list packet arival
            print("Got a packet " + str(num))  # +":", packet.summary())
            if self.intercepting:
                id = time.time()  # self.getID()
                if self.is_outgoing:
                    test_frame = Frame(self.tbmg.netqueueframeS.interior)
                else:
                    test_frame = Frame(self.tbmg.netqueueframeR.interior)
                summary = packet.summary()
                if len(summary) > 140:
                    summary = summary[:140] + "\n" + summary[140:]
                button = Button(test_frame, text=str(num) + ":" + summary,
                                width="80", command=lambda: skipAhead(num))
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
                
                # TODO check queue gui
                def checkReorderQueue():
                    print 'check order...'
                    numbers = []
                    queue_gui = self.tbmg.netqueueframeS.interior if self.is_outgoing else self.tbmg.netqueueframeR.interior
                    for frame in queue_gui.winfo_children():
                        if not frame.winfo_children():
                            continue
                        #print 'frame slaves:',frame,frame.winfo_children()
                        pack_button = frame.grid_slaves()[0]
                        #print 'got back button',pack_button
                        order_number = int(pack_button.cget('text').split(':')[0])
                        for n in numbers:
                            if order_number > n:
                                return True
                        numbers.append(order_number)
                    return False
                
                def reorderQueue():
                    print 'REORDERING!!!!!!!!!!'
                    queue_gui = self.tbmg.netqueueframeS.interior if self.is_outgoing else self.tbmg.netqueueframeR.interior
                    all_frames = queue_gui.winfo_children()
                    for item in all_frames:
                        if not item.winfo_children():
                            all_frames.remove(item)
                    ordered_frames = [all_frames[0]]
                    del (all_frames[0])
                    queue_gui.pack_forget()
                    for frame in all_frames:
                        pack_button = frame.grid_slaves()[0]
                        a = int(pack_button.cget('text').split(':')[0])
                        i = 0
                        added = True
                        for ordered in ordered_frames:
                            b = int(ordered.grid_slaves()[0].cget('text').split(':')[0])
                            added = a < b
                            if added:
                                ordered_frames.insert(i, pack_button)
                                break
                            i = i+1
                        if not added:
                            ordered_frames.append(pack_button)
                    
                    for frame in ordered_frames:
                        frame.pack()
                if checkReorderQueue():
                    reorderQueue()
                
                
                
                #self.packet_queue.append([1, packet, id, button, timelabel])
            
            # lock - one at a time get to render,
            print 'want lock'
            self.display_lock.acquire()
            print 'got lock for ',str(num)
            if not self.status:
                print 'I should not be on...'
                try:
                    test_frame.destroy()
                    self.tbmg.timers.remove(timelabel)
                except:
                    pass
                self.display_lock.release()
                if data:
                    return data, interceptor.NF_ACCEPT
                elif self.intercepting:
                    #sendp(packet)
                    return
            #if self.skip_to_pack_num:
            if num < self.skip_to_pack_num:
                print 'skipping! im at', str(num)
                test_frame.destroy()
                self.tbmg.timers.remove(timelabel)
                self.display_lock.release()
                if data:
                    return data, interceptor.NF_ACCEPT
                else:
                    #sendp(packet)
                    return
            elif num == self.skip_to_pack_num:
                print 'hit num.im at',str(num)
                self.skip_to_pack_num=0
            
            self.current_pack = packet
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
                
                recv = self.child_conn.recv()
                if recv == 'drop':
                    print 'DROPING'
                    self.display_lock.release()
                    test_frame.destroy()
                    self.tbmg.timers.remove(timelabel)
                    #TODO efficently delte self from packet queue
                    if data:
                        return data, interceptor.NF_DROP
                elif recv == 'accept':
                    print "ACCEPTING",str(num)
                    try:
                        self.clearDisect()
                    except:
                        pass
                    self.clearRaw()
                    self.display_lock.release()
                    test_frame.destroy()
                    self.tbmg.timers.remove(timelabel)
                    if data:
                        return data, interceptor.NF_ACCEPT
                    elif self.intercepting:
                        #sendp(packet)
                        return
                elif recv == 'raw':
                    recv = str(self.child_conn.recv())
                    #TODO make more definite way...
                    if data:
                        self.current_pack = Ether(recv[:recv.index('450000')].decode('hex'))/ IP(recv[recv.index('450000'):].decode('hex'))
                    else:
                        self.current_pack = Ether(recv)#TODO check if arp gets this
                elif recv == 'disect':#already been modded
                    pass
                
                # fix chksum and len
                try:
                    del (self.current_pack['IP'].chksum)
                except:
                    pass
                try:
                    del (self.current_pack['TCP'].chksum)
                except:
                    pass
                #TODO check chksum.....
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
                        sendp(self.current_pack)
                        test_frame.destroy()
                        self.display_lock.release()
                        return raw(self.current_pack), interceptor.NF_DROP
                    elif self.intercepting:
                        sendp(self.current_pack)
                        self.display_lock.release()
                        return
                # TODO efficently delte self from packet queue
                if data:
                    self.display_lock.release()
                    return raw(self.current_pack['IP']), interceptor.NF_ACCEPT
                elif self.intercepting:
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
                self.display_lock.release()
            except:
                pass
