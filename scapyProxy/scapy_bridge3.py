"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

from Tkinter import *
from scapy.all import *
import os
import threading
from multiprocessing import Pipe
import time
from scapyProxy.GuiUtils import VerticalScrolledFrame
from socket import gaierror
import chardet
import interceptor
from StringIO import StringIO
import sys

class ScapyBridge(object):
    
    def __init__(self, tbmg_):
        # output catches outgoing packets, input from other machines, and forward for mitm
        self.iptablesr = "iptables -A OUTPUT -j NFQUEUE --queue-num 0; iptables -A FORWARD -j NFQUEUE --queue-num 0; iptables -A INPUT -j NFQUEUE --queue-num 0"
        #self.iptablesr = ""#""iptables -t nat -A PREROUTING -j NFQUEUE --queue-num 2"
        #self.iptablesr = 'iptables -I OUTPUT 1 -j NFQUEUE --queue-balance 0:2; iptables -I FORWARD 1 -j NFQUEUE --queue-balance 0:2; iptables -I INPUT 1 -j NFQUEUE --queue-balance 0:2;'
        #self.iptablesr = 'iptables -I OUTPUT 1 -j NFQUEUE --queue-num 0; iptables -I FORWARD 2 -j NFQUEUE --queue-num 0; iptables -I INPUT 3 -j NFQUEUE --queue-num 0'
        self.tbmg = tbmg_
        self.q = None
        self.status = False
        self.filter = None
        self.parent_conn, self.child_conn = Pipe()
        self.pcapfile = ''
        self.intercepting = False
        self.gui_layers = {}  # gui_layers['IP'] = [(Label(text=layer),Label(text=feild_name),Entry(text=feild_value)),(L,E),...]
        self.current_pack = None
        self.sock = None
        self.intercepter = interceptor.Interceptor()
        
    def sendDrop(self):
        if self.intercepting:
            self.parent_conn.send('drop')
    
    def sendRawUpdate(self):
        if self.intercepting:
            text = str(self.tbmg.rawtext.get('0.0', END)).strip()
            print 'updating to:', text
            self.parent_conn.send('raw')
            self.parent_conn.send(text)
    
    def sendDisectUpdate(self):
        if not self.intercepting:
            return
        #print 'current:', str(raw(self.current_pack)).encode('hex')
        if not self.gui_layers or len(self.tbmg.disectlist.interior.grid_slaves()) < 2:
            return
        for layer in self.gui_layers:
            if layer and layer in self.current_pack:
                for pair in self.gui_layers[layer]:
                    type1 = getattr(self.current_pack[layer], pair[1].cget('text'))  # correct type for feild
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
                            if int(value[1:-1], 16):
                                value = '"' + value[1:-1].decode('hex') + '"'
                                print('found HEX', value)
                    except Exception:
                        pass
                        # print value,'not HEX',e
                    if '['in value and ']'in value:#type(value) == str and len(value) >= 4 and value[1] == '[' and value[-2] == ']' and type1 == type([]):
                        #print 'found array type:'+value
                        value = value[1:-1]
                    elif value == '"None"':
                        if type1 == type(None):
                            continue
                        if type1 == int:
                            value = '0'
                        else:
                            value = 'None'
                    elif value == '""':
                        value = 'None'
                    if layer == 'Raw' and pair[1].cget('text') == 'load':  # ping 8.8.4.4
                        if not self.current_pack[layer].load == value[1:-1].decode('hex'):
                            print("FOUND CHANGE in RAW!!!", value, value.encode('hex'))
                            print(self.current_pack['Raw'].load, self.current_pack['Raw'].load.encode('hex'))
                            print('------------------')
                            continue  # use default val
                        self.current_pack['Raw'].load = value[1:-1].decode('hex')
                        continue
                    #('checking if equal:', 'self.current_pack[\'DNS\'].qd == "\ndiscordapp\x03com"')
                    #self.current_pack['DNS'].qd == "
                    # TODO add protocol exceptions here!
                    #set value to packet
                    #execute = "self.current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
                    #print('setting:', execute)
                    try:
                        if getattr(self.current_pack[layer], pair[1].cget('text')) != eval(value):
                            execute = "self.current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
                            #print('setting:', execute)
                            #print 'oldval->',getattr(self.current_pack[layer],pair[1].cget('text')),type(getattr(self.current_pack[layer],pair[1].cget('text')))
                            setattr(self.current_pack[layer], pair[1].cget('text'), eval(value))
                            print 'newval->',getattr(self.current_pack[layer],pair[1].cget('text')),type(getattr(self.current_pack[layer],pair[1].cget('text')))
                    except Exception, e:
                        print 'setattr err:',e,'->',"self.current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
        r = raw(self.current_pack)
        print('producing from disect:', r.encode('hex'))
        self.parent_conn.send(r)
        self.gui_layers = None
        self.clearDisect()
        self.clearRaw()
    
    def clearDisect(self):
        for w in self.tbmg.disectlist.interior.grid_slaves():
            w.destroy()
    
    def clearRaw(self):
        self.tbmg.rawtext.delete(1.0, END)
    
    def _packet_disect_intercept(self, pack):
        self.clearDisect()
        self.gui_layers = {}
        rownum = 1
        #$pack.show()
        for i in range(10):
            try:
                l = pack.getlayer(i)
                if not l:
                    continue
                self.gui_layers[l.name] = []
                layer = Label(self.tbmg.disectlist.interior, text=l.name)
                layer.grid(row=rownum, column=0)
                rownum += 1
                if l.name == 'Ethernet' or l.name == 'Ether':
                    label = Label(self.tbmg.disectlist.interior, text='src')
                    label.grid(row=rownum, column=1)
                    entry = Entry(self.tbmg.disectlist.interior, width=30)
                    entry.grid(row=rownum, column=2)
                    entry.insert(0, str(pack[0].src).encode('utf8'))
                    self.gui_layers[l.name].append((layer, label, entry))
                    rownum += 1
                    
                    label = Label(self.tbmg.disectlist.interior, text='dst')
                    label.grid(row=rownum, column=1)
                    entry = Entry(self.tbmg.disectlist.interior, width=30)
                    entry.grid(row=rownum, column=2)
                    entry.insert(0, str(pack[0].dst).encode('utf8'))
                    self.gui_layers[l.name].append((layer, label, entry))
                    rownum += 1
                    
                    label = Label(self.tbmg.disectlist.interior, text='type')
                    label.grid(row=rownum, column=1)
                    entry = Entry(self.tbmg.disectlist.interior, width=30)
                    entry.grid(row=rownum, column=2)
                    entry.insert(0, str(pack[0].type).encode('utf8'))
                    self.gui_layers[l.name].append((layer, label, entry))
                    rownum += 1
                    continue
                    
                for f in l.fields:
                    label = Label(self.tbmg.disectlist.interior, text=str(f))
                    label.grid(row=rownum, column=1)
                    entry = Entry(self.tbmg.disectlist.interior, width=30)
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
        # self.tbmg.update()
    
    def _packet_disect_nointercept(self, pack):
        capture = StringIO()
        save_stdout = sys.stdout
        sys.stdout = capture
        pack.show()
        sys.stdout = save_stdout
        return capture.getvalue()+'\n----------------------------------\n'
    
    def interceptToggle(self):
        if self.intercepting:
            self.parent_conn.send('drop')
            time.sleep(.1)
            while self.child_conn.poll():
                self.child_conn.recv()
            self.clearRaw()
            self.clearDisect()
        self.intercepting = not self.intercepting
        print 'intercpet is now', self.intercepting
        
        def addnointercptGUI():
            self.tbmg.disecttext = Text(self.tbmg.page5, height=50, width=55)
            self.tbmg.disecttextscroll = Scrollbar(self.tbmg.page5)
            self.tbmg.disecttextscroll.config(command=self.tbmg.disecttext.yview)
            self.tbmg.disecttext.config(yscrollcommand=self.tbmg.disecttextscroll.set)
            self.tbmg.disecttext.grid(row=3, column=2)
            self.tbmg.disecttextscroll.grid(row=3, column=3)
            self.tbmg.disecttext.insert(END, 'DISECT\n---\n')
        
        def addintercptGUI():
            self.tbmg.disectlist = VerticalScrolledFrame(self.tbmg.page5, height=100, width=50)
            self.tbmg.disectlist.grid(row=3, column=2)
            self.tbmg.disectLable = Label(self.tbmg.disectlist.interior, text='DISECT VIEW\n----\n')
            self.tbmg.disectLable.grid(row=0, column=0)
        
        if self.intercepting:
            if self.tbmg.disecttext or self.tbmg.disecttextscroll:
                self.tbmg.disecttext.destroy()
                self.tbmg.disecttext = None
                self.tbmg.disecttextscroll.destroy()
                self.tbmg.disecttextscroll = None
            if self.tbmg.disectlist and self.tbmg.disectLable:
                pass
            else:
                addintercptGUI()
        else:
            if self.tbmg.disectlist or self.tbmg.disectLable:
                self.tbmg.disectlist.destroy()
                self.tbmg.disectlist = None
                self.tbmg.disectLable.destroy()
                self.tbmg.disectLable = None
            if self.tbmg.disecttext and self.tbmg.disecttextscroll:
                pass
            else:
                addnointercptGUI()
    
    def proxyToggle(self):
        #print(not self.status)
        self.status = not self.status
        if self.status:
            try:
                print("Adding iptable rules :")
                print(self.iptablesr)
                os.system(self.iptablesr)
                self.intercepter = interceptor.Interceptor()
                try:
                    print 'about to start proxy'
                    self.intercepter.start(self.callback, queue_ids=[0])
                    print ('moving after proxy start')
                except Exception, e:
                    print 'COUNDT START PROXY',e
                    print("Flushing iptables.")
                    # This flushes everything, you might wanna be careful
                    # may want a way to restore tables after
                    os.system('iptables -F')
                    os.system('iptables -X')
            except Exception, e:
                print 'start proxy err', e
        else:
            try:
                print 'droping packs'
                #clean gui
                if self.intercepting:
                    for i in range(20):
                        self.parent_conn.send('drop')
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
                self.intercepter.stop()
                
            except Exception, e:
                print 'proxy err:',e
                pass

    # ran from seperate process
    def callback(self, ll_data, ll_proto_id, data, ctx):
        # Here is where the magic happens.
        if not self.status:
            print 'I should not be on...'
            return data, interceptor.NF_DROP
        eth = Ether(ll_data)
        self.current_pack = eth/IP(data)#eth/IP(data)
        org = eth/IP(data)
        print("Got a packet:",self.current_pack.summary())
        dofilter = False  # show package in gui when = True
        if self.filter:
            try:
                dofilter = bool(sniff(offline=self.current_pack['IP'], filter=self.filter))
                print 'filter:',dofilter
                if not dofilter:
                    return data, interceptor.NF_ACCEPT
            except Exception, e:
                print 'Filter err:', self.filter, e
                return data, interceptor.NF_ACCEPT
        
        if self.intercepting:
            print 'intercepting'
            if self.filter and not dofilter:
                print 'intercept, but not in filter'
                if self.pcapfile:
                    wrpcap(self.pcapfile, self.current_pack, append=True)
                    wrpcap(self.pcapfile[:-5] + '_mod.pcap', self.current_pack, append=True)
                return data, interceptor.NF_ACCEPT
            self.clearDisect()
            self.clearRaw()
            self._packet_disect_intercept(self.current_pack)
            self.tbmg.rawtext.insert('0.0', str(raw(self.current_pack)).encode('hex'))
            #recive data from GUI
            recv = self.child_conn.recv()
            if recv == 'drop':
                print 'DROPING'
                return data, interceptor.NF_DROP
            elif recv == 'raw':
                recv = str(self.child_conn.recv())
                self.current_pack = Ether(recv[:recv.index('450000')].decode('hex'))/ IP(recv[recv.index('450000'):].decode('hex'))
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
            try:
                del (self.current_pack['ICMP'].chksum)
            except:
                pass
            self.current_pack = self.current_pack.__class__(str(self.current_pack))
            #handle updated packet
            if self.pcapfile:
                wrpcap(self.pcapfile, org, append=True)
                wrpcap(self.pcapfile[:-5] + '_mod.pcap', self.current_pack, append=True)
            print 'sending updated....',raw(self.current_pack)
            print 'rather than........',data
            #TODO if eth layer changed, NF_DROP and use scapy to send self.current_pack
            return raw(self.current_pack['IP']), interceptor.NF_ACCEPT
        else:
            print 'not intercpeting..'
            self.tbmg.disecttext.insert('3.0', self._packet_disect_nointercept(self.current_pack))
            self.tbmg.rawtext.insert('0.0', '\n- ' + str(raw(self.current_pack)).encode('hex'))
            if self.pcapfile:
                wrpcap(self.pcapfile, self.current_pack, append=True)
                wrpcap(self.pcapfile[:-5] + '_mod.pcap', self.current_pack, append=True)
            return raw(self.current_pack['IP']), interceptor.NF_ACCEPT
